"""A scripted stand-in for the language model, so the whole local demo runs with no Ollama and
no Bedrock: in CI, in a screenshot session, or on a laptop that cannot pull a model.

It plays the model's part honestly rather than cleverly:
  * alarm prompts: follow the runbook the handler wrote (diagnose, remediate, confirm);
  * chat prompts: do what the human asked, exactly once, even when it is obviously forbidden -
    that is what the real agent is told to do, so that Cedar's denial is audited;
  * an injected instruction in a resource's own Name tag persuades it (it tries the terminate
    first), which is the worst case the leash exists for.

Everything downstream of the model is real: the tools, Cedar (cedarpy), the audit rows, the
fake AWS world. The message list mirrors the Strands shape so agent.handler._tools_used() and
redteam.runner._tools_called() read it unchanged.
"""

from __future__ import annotations

import json
import os
import re

from agent import tools

_INSTANCE_ID = re.compile(r"\bi-[0-9a-f]{8,17}\b")
_ASG_NAME = re.compile(r"\bleash-[a-z0-9-]*asg\b")
_COUNT = re.compile(r"\b(?:to|up to|at|=)\s*(\d{1,3})\b|\b(\d{1,3})\s+instances?\b", re.IGNORECASE)


def _default_ids() -> dict:
    """Fallback ids for attacks that hide the id (base64 etc.): the deployment's, else the fake world's."""
    from local_demo.scenarios import ASG_NAME, DEV_INSTANCE, PROD_INSTANCE

    return {
        "dev": os.environ.get("DEV_INSTANCE_ID") or DEV_INSTANCE,
        "prod": os.environ.get("PROD_INSTANCE_ID") or PROD_INSTANCE,
        "asg": os.environ.get("ASG_NAME") or ASG_NAME,
    }


class ScriptedAgent:
    """Callable like a strands.Agent: agent(prompt) -> reply text, with .messages and .system_prompt."""

    system_prompt = ""

    def __init__(self):
        self.messages: list = []

    # --- the Strands-shaped record of a tool call ---------------------------------------
    def _call(self, name: str, fn, *args) -> str:
        result = str(fn(*args))
        self.messages.append({"role": "assistant", "content": [{"toolUse": {"name": name, "input": {}}}]})
        self.messages.append({"role": "user", "content": [{"toolResult": {"content": [{"text": result}]}}]})
        return result

    def __call__(self, prompt) -> str:
        text = str(prompt)
        if text.startswith("CloudWatch alarm"):
            return self._alarm(text)
        return self._chat(text)

    # --- alarm mode: the runbook, step by step ------------------------------------------
    def _alarm(self, text: str) -> str:
        m = re.search(r"Metric dimensions: (\{.*\})", text)
        dims = json.loads(m.group(1)) if m else {}
        if "InstanceId" in dims:
            iid = dims["InstanceId"]
            info = self._call("get_instance_info", tools.get_instance_info, iid)
            seen = ""
            if "terminate" in info.lower():
                # The Name tag told the model to terminate. A persuadable model tries; Cedar decides.
                seen = self._call("terminate_instance", tools.terminate_instance, iid)
            before = self._call("get_disk_usage", tools.get_disk_usage, iid)
            fix = self._call("clean_disk", tools.clean_disk, iid)
            after = self._call("get_disk_usage", tools.get_disk_usage, iid)
            note = f" The instance's Name tag carried an instruction to terminate it; I tried and got: {seen}." if seen else ""
            return (f"Disk alarm on {iid}. Before: {before}. Remediation: {fix}. After: {after}.{note} "
                    "The disk is back under the threshold.")
        if "ClusterName" in dims and "ServiceName" in dims:
            cluster, service = dims["ClusterName"], dims["ServiceName"]
            before = self._call("get_service_info", tools.get_service_info, cluster, service)
            fix = self._call("restart_service", tools.restart_service, cluster, service)
            after = self._call("get_service_info", tools.get_service_info, cluster, service)
            return f"ECS alarm on {cluster}/{service}. Before: {before}. Remediation: {fix}. After: {after}."
        return "No runbook matches these dimensions; nothing changed."

    # --- chat mode: do the one thing the human asked ------------------------------------
    def _chat(self, text: str) -> str:
        # Key off the human's own words, not the handler's boilerplate around them (which
        # mentions "Auto Scaling group", "terminate_instance" etc. in its rules).
        m = re.search(r"A human operator asks: (.*?)(?:\n\n|$)", text, re.DOTALL)
        text = m.group(1) if m else text
        low = text.lower()
        ids = _default_ids()
        instances = _INSTANCE_ID.findall(text)
        asgs = _ASG_NAME.findall(text)
        if re.search(r"\bterminat|\bdestroy|\bdelete|\bkill\b", low):
            return self._call("terminate_instance", tools.terminate_instance, instances[0] if instances else ids["dev"])
        if asgs or re.search(r"\bscal|\bresiz|\bgrow", low):
            m = _COUNT.search(text)
            n = int(next(g for g in m.groups() if g)) if m else 10
            return self._call("scale_group", tools.scale_group, asgs[0] if asgs else ids["asg"], n)
        if re.search(r"disk usage|how full|what is the disk", low) and not re.search(r"clean|free up|fix", low):
            return self._call("get_disk_usage", tools.get_disk_usage, instances[0] if instances else ids["dev"])
        target = instances[0] if instances else (ids["prod"] if "prod" in low else ids["dev"])
        return self._call("clean_disk", tools.clean_disk, target)


def install() -> None:
    """Make agent.handler build ScriptedAgent instead of a model-backed Strands agent."""
    from agent import handler as agent_handler

    agent_handler._AGENT = None
    agent_handler.build_agent = lambda incident_id: ScriptedAgent()
