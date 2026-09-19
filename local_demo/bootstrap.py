"""One place that wires up an entirely local Leash: env vars, src/ on sys.path, fake AWS,
fake Lambda-invoke, and (optionally) waits for Ollama to have the model ready.

Import and call setup() before importing anything from `agent` or `api` - the env vars below
must exist before agent.agent.build_agent() reads them.
"""

import os
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"

DEFAULTS = {
    "LEASH_LOCAL_AUTHZ": "1",      # src/common/authz.py -> evaluate cedar/policies/*.cedar with cedarpy
    "LEASH_LOCAL_MODEL": "1",      # src/agent/agent.py  -> OllamaModel instead of BedrockModel
    "OLLAMA_HOST": "http://localhost:11434",
    "OLLAMA_MODEL_ID": "llama3.2:3b",
    "AWS_REGION": "us-east-1",
    "AUDIT_TABLE": "local-leash-audit",     # name only; the real table is local_demo.fake_aws.WORLD
    "ALERT_TOPIC_ARN": "local-leash-alerts",
    "AGENT_FUNCTION_NAME": "local-leash-agent",  # name only; local_lambda.py never looks it up
    "ENV_TAG_KEY": "env",
    "SCALE_CAP": "4",
}


def setup(reset_world: bool = True):
    for key, value in DEFAULTS.items():
        os.environ.setdefault(key, value)
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    from local_demo import fake_aws, local_lambda

    if reset_world:
        fake_aws.reset()
        _use_scratch_policy_store()
    fake_aws.install()
    local_lambda.install()
    return fake_aws.WORLD


def _use_scratch_policy_store():
    """Point the authorizer at a throwaway copy of cedar/ so approving a proposed policy (#21)
    is real - enforced on the next decision - without ever touching the repo's own files."""
    import shutil
    import tempfile

    current = os.environ.get("LEASH_CEDAR_DIR")
    if current and current not in _SCRATCH_DIRS:
        return  # the operator pointed at a store of their own; respect it
    scratch = Path(tempfile.mkdtemp(prefix="leash-cedar-")) / "cedar"
    shutil.copytree(REPO_ROOT / "cedar", scratch)
    os.environ["LEASH_CEDAR_DIR"] = str(scratch)
    _SCRATCH_DIRS.add(str(scratch))  # a later reset replaces it, so approvals never leak across runs
    from common import authz

    authz._LOCAL.clear()


_SCRATCH_DIRS: set = set()


def ollama_ready(model_id: str | None = None, timeout: float = 2.0) -> tuple[bool, str]:
    """Best-effort check that `ollama serve` is up and the model has been pulled."""
    model_id = model_id or os.environ.get("OLLAMA_MODEL_ID", DEFAULTS["OLLAMA_MODEL_ID"])
    host = os.environ.get("OLLAMA_HOST", DEFAULTS["OLLAMA_HOST"])
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=timeout) as resp:
            import json

            tags = json.loads(resp.read())
        names = [m.get("name", "") for m in tags.get("models", [])]
        if any(n == model_id or n.startswith(model_id.split(":")[0] + ":") for n in names):
            return True, f"ollama is up and {model_id} is available"
        return False, f"ollama is up but {model_id} is not pulled yet (have: {names or 'none'})"
    except Exception as exc:  # noqa: BLE001 - this is a friendly pre-flight check, not a hard dependency
        return False, f"could not reach ollama at {host}: {exc}"
