"""Test setup for local_demo: repo root (for `local_demo`) and src/ (for agent/api/common) on
sys.path, same env defaults as the other suites. No model, no AWS."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

os.environ.setdefault("LEASH_LOCAL_AUTHZ", "1")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
