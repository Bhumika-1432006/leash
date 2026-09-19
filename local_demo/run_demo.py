#!/usr/bin/env python
"""Run one, several, or all Leash demo scenarios entirely locally: no AWS account, no Docker.

Usage (from the repo root):
    python local_demo/run_demo.py list
    python local_demo/run_demo.py disk-full
    python local_demo/run_demo.py all
    python local_demo/run_demo.py disk-full ecs-down ask-terminate
    python local_demo/run_demo.py all --scripted     # no model: a scripted agent plays its part

What actually runs for real, not mocked: the Strands agent (on a local Ollama model), the real
Cedar policies (evaluated by cedarpy against cedar/policies/*.cedar + cedar/schema.json), and
every line of src/agent and src/common. Only AWS itself is faked (local_demo/fake_aws.py).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from local_demo import bootstrap  # noqa: E402


def _hr(char="-", width=78):
    print(char * width)


def run_one(key: str, world) -> None:
    from local_demo.scenarios import BY_KEY

    scenario = BY_KEY[key]
    _hr("=")
    print(scenario.title)
    print(f"  {scenario.note}")
    _hr()
    scenario.setup(world)

    before_n = len(world.audit_items)
    from agent import handler as handler_mod
    from agent.handler import handler

    # Each scenario is a distinct incident by construction, so the duplicate-alarm cooldown
    # (one remediation per alarm transition) must not make scenario 6 skip scenario 1's alarm.
    handler_mod._RECENT.clear()
    print(f"-> sending event: {json.dumps(scenario.event)[:160]}...")
    result = handler(scenario.event, None)
    print(f"\nagent reply (incident {result['incident_id']}):\n")
    print("  " + str(result["reply"]).replace("\n", "\n  "))

    new_rows = world.audit_items[before_n:]
    if new_rows:
        from common.audit import _deserialize  # rows are stored DynamoDB-typed, same as production

        print(f"\naudit rows written this run ({len(new_rows)}):")
        for raw in new_rows:
            row = _deserialize(raw)
            print(f"  [{row['decision']:5s}] {row['action']:20s} {row['resource_id']:28s} "
                  f"env={row['resource_env']:6s} policies={row['policy_ids']}")
    if world.notifications:
        subj, msg = world.notifications[-1]
        print(f"\nsns notify: {subj}\n  {msg[:200]}")
    print(f"\nworld state: disk[dev]={world.instances['i-0de70000000000001']['disk_used_percent']:.0f}%  "
          f"ecs running={world.ecs_services[('leash-dev', 'leash-api-dev')]['running']}  "
          f"asg desired={world.asgs['leash-dev-asg']['desired']}")
    _hr("=")
    print()


def main(argv: list[str]) -> int:
    from local_demo.scenarios import SCENARIOS

    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "list":
        for s in SCENARIOS:
            print(f"  {s.key:20s} {s.title}")
        return 0

    scripted = "--scripted" in argv
    argv = [a for a in argv if a != "--scripted"]

    if scripted:
        print("[ok] scripted agent: no model, no Ollama - a scripted stand-in plays the model's part")
    else:
        ready, msg = bootstrap.ollama_ready()
        print(("[ok] " if ready else "[!!] ") + msg)
        if not ready:
            print("      Start it with: ollama serve   (in another terminal), and make sure the "
                  "model is pulled: ollama pull llama3.2:3b - or add --scripted to run with no model.")
            print("      Continuing anyway - a failed agent call is caught and reported as text, "
                  "it will not crash this script.")

    world = bootstrap.setup(reset_world=True)
    if scripted:
        from local_demo import scripted_agent

        scripted_agent.install()

    from local_demo.scenarios import BY_KEY

    keys = [s.key for s in SCENARIOS] if argv[0] == "all" else argv
    unknown = [k for k in keys if k not in BY_KEY]
    if unknown:
        print(f"unknown scenario(s): {unknown}. Run 'list' to see valid keys.")
        return 1

    for key in keys:
        run_one(key, world)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
