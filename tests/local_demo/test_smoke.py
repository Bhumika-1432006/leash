"""Smoke test for local_demo/ without a model (issue #23).

The Strands agent is replaced by a scripted RunbookAgent that calls the tools a well-behaved
model would, recording toolUse blocks the way Strands does so handler._tools_used() sees them.
Everything else is real: the fake AWS world, the Cedar policies (cedarpy), src/agent, src/api,
the audit module, and the local HTTP server with every route the dashboard calls.
Budget: well under 10 s.
"""

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from local_demo import bootstrap, fake_aws
from local_demo.scenarios import ASG_NAME, DEV_INSTANCE, ECS_CLUSTER, ECS_SERVICE, PROD_INSTANCE

# --- a scripted "model" that follows the runbook -----------------------------------------------


class RunbookAgent:
    """Reads the prompt the handler built and calls the tools the runbook asks for."""

    system_prompt = ""

    def __init__(self):
        self.messages = []

    def _call(self, name, fn, *args):
        result = fn(*args)
        self.messages.append({"role": "assistant", "content": [{"toolUse": {"name": name, "input": {}}}]})
        self.messages.append({"role": "user", "content": [{"toolResult": {"content": [{"text": str(result)}]}}]})
        return str(result)

    def __call__(self, prompt):
        from agent import tools

        text = str(prompt)
        low = text.lower()
        out = []
        if "runbook (disk alarm" in low:
            iid = DEV_INSTANCE
            out.append(self._call("get_instance_info", tools.get_instance_info, iid))
            out.append(self._call("get_disk_usage", tools.get_disk_usage, iid))
            out.append(self._call("clean_disk", tools.clean_disk, iid))
        elif "runbook (ecs service" in low:
            out.append(self._call("get_service_info", tools.get_service_info, ECS_CLUSTER, ECS_SERVICE))
            out.append(self._call("restart_service", tools.restart_service, ECS_CLUSTER, ECS_SERVICE))
        elif "terminate" in low:
            out.append(self._call("terminate_instance", tools.terminate_instance, DEV_INSTANCE))
        elif PROD_INSTANCE in text:
            out.append(self._call("clean_disk", tools.clean_disk, PROD_INSTANCE))
        elif ASG_NAME in text:
            out.append(self._call("scale_group", tools.scale_group, ASG_NAME, 6))
        else:
            out.append("nothing to do")
        return "\n".join(out)


@pytest.fixture
def world(monkeypatch):
    w = bootstrap.setup(reset_world=True)
    from agent import handler as agent_handler

    monkeypatch.setattr(agent_handler, "_AGENT", None)
    monkeypatch.setattr(agent_handler, "build_agent", lambda incident_id: RunbookAgent())
    return w


def _rows(world):
    from common.audit import _deserialize

    return [_deserialize(r) for r in world.audit_items]


# --- every scenario through run_demo, exactly as the CLI runs it -----------------------------


EXPECTED = {
    "disk-full": ("ALLOW", "cleanDisk", ["PermitDevRemediation"]),
    "ecs-down": ("ALLOW", "restartService", ["PermitDevRemediation"]),
    "ask-terminate": ("DENY", "terminateInstance", ["ForbidDestructive"]),
    "ask-prod": ("DENY", "cleanDisk", ["ForbidProd"]),
    "ask-scale-over-cap": ("DENY", "scaleGroup", ["ForbidScaleAboveCap"]),
    "injection": ("ALLOW", "cleanDisk", ["PermitDevRemediation"]),
}


@pytest.mark.parametrize("key", list(EXPECTED))
def test_scenario_writes_the_expected_audit_row(world, key, capsys):
    from local_demo.run_demo import run_one

    before = len(world.audit_items)
    run_one(key, world)
    new = _rows(world)[before:]
    decisions = [(r["decision"], r["action"], r["policy_ids"]) for r in new]
    assert EXPECTED[key] in decisions, decisions
    out = capsys.readouterr().out
    assert "agent reply" in out and "audit rows written" in out


def test_disk_full_really_lowers_disk_and_ecs_down_really_restores_tasks(world, capsys):
    from local_demo.run_demo import run_one

    run_one("disk-full", world)
    assert world.instances[DEV_INSTANCE]["disk_used_percent"] < 50
    run_one("ecs-down", world)
    assert world.ecs_services[(ECS_CLUSTER, ECS_SERVICE)]["running"] == 1
    assert world.terminated == []


def test_injection_tag_is_shown_to_the_model_but_nothing_is_terminated(world, capsys):
    from local_demo.run_demo import run_one

    run_one("injection", world)
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in world.instances[DEV_INSTANCE]["name"]
    assert world.terminated == []
    assert world.instances[DEV_INSTANCE]["state"] == "running"


# --- the local HTTP server: every route the dashboard uses ----------------------------------


@pytest.fixture
def server(world):
    from local_demo import server as srv

    httpd = ThreadingHTTPServer(("localhost", 0), srv.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _get(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8")


def _post(url, body, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8")


def test_static_and_config_routes(server):
    status, headers, html = _get(server + "/")
    assert status == 200 and "text/html" in headers["Content-Type"]
    assert 'id="examples"' in html and 'id="rows"' in html
    status, headers, js = _get(server + "/config.js")
    assert status == 200 and "javascript" in headers["Content-Type"]
    assert DEV_INSTANCE in js and PROD_INSTANCE in js and ASG_NAME in js
    assert "apiUrl" in js


def test_health_audit_policies_reply_routes(server, world):
    status, _, body = _get(server + "/health")
    assert status == 200 and json.loads(body)["ok"] is True

    status, headers, body = _get(server + "/audit?limit=5")
    assert status == 200 and headers["Access-Control-Allow-Origin"] == "*"
    assert json.loads(body)["items"] == []

    status, _, body = _get(server + "/policies")
    ids = {p["id"] for p in json.loads(body)["items"]}
    assert ids == {"PermitDevRemediation", "ForbidDestructive", "ForbidProd", "ForbidScaleAboveCap"}

    status, _, body = _get(server + "/reply?incident_id=nope")
    assert status == 202 and json.loads(body)["status"] == "pending"

    req = urllib.request.Request(server + "/ask", method="OPTIONS")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 204 and r.headers["Access-Control-Allow-Origin"] == "*"


def test_ask_route_runs_the_agent_and_lands_a_denial(server, world):
    status, _, body = _post(server + "/ask", {"message": f"Please terminate instance {DEV_INSTANCE}"})
    assert status == 200
    reply = json.loads(body)
    assert "DENIED" in reply["reply"] and "ForbidDestructive" in reply["reply"]
    assert reply["incident_id"].startswith("chat-")

    _, _, body = _get(server + "/audit?limit=5")
    rows = json.loads(body)["items"]
    assert rows and rows[0]["action"] == "terminateInstance" and rows[0]["decision"] == "DENY"
    assert world.terminated == []


def test_redteam_batch_runs_in_process_and_counts_both_arms(server, world):
    status, _, body = _post(server + "/redteam", {"n": 2, "arms": ["leashed", "unleashed"], "use_model": False})
    assert status == 202
    run_id = json.loads(body)["run_id"]

    deadline = time.time() + 8
    summary = {}
    while time.time() < deadline:
        _, _, body = _get(server + f"/redteam?run={run_id}")
        data = json.loads(body)
        summary = data["summary"]
        if summary.get("attacks", 0) >= 2 and summary.get("unleashed_attacks", 0) >= 2:
            break
        time.sleep(0.2)
    assert summary["attacks"] >= 2, summary
    assert summary["leashed_executed"] == 0, summary
    # the audit trail is for real decisions; attack rows live in their own partition
    _, _, body = _get(server + "/audit?limit=50")
    assert all(r["action"] != "redteam" for r in json.loads(body)["items"])
