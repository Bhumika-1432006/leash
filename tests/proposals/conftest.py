"""English -> Cedar tests: repo root + src on sys.path, a scratch copy of cedar/ per test so
approving is real (enforced on the next decision) and never touches the repo's files."""

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

os.environ.setdefault("LEASH_LOCAL_AUTHZ", "1")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AUDIT_TABLE", "leash-audit-test")


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A throwaway cedar/ the authorizer reads from; the fake DynamoDB holds the proposals."""
    scratch = tmp_path / "cedar"
    shutil.copytree(ROOT / "cedar", scratch)
    monkeypatch.setenv("LEASH_CEDAR_DIR", str(scratch))
    monkeypatch.delenv("LEASH_CEDAR_S3_BUCKET", raising=False)
    monkeypatch.delenv("REQUEST_QUEUE_URL", raising=False)
    monkeypatch.setenv("LEASH_SCRIPTED_AGENT", "1")  # no model: template drafting only
    from local_demo import fake_aws
    from common import authz

    fake_aws.reset()
    fake_aws.install()
    authz._LOCAL.clear()
    authz._S3.clear()
    return scratch
