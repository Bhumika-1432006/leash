"""The two routes that change what the system does need the operator token; everything else does not."""

import json

import pytest

from api import handler as h


class FakeSqs:
    def __init__(self):
        self.sent = []

    def send_message(self, QueueUrl, MessageBody):
        self.sent.append(json.loads(MessageBody))
        return {"MessageId": "m1"}


@pytest.fixture
def worker_mode(monkeypatch):
    sqs = FakeSqs()
    monkeypatch.setenv("REQUEST_QUEUE_URL", "https://sqs/leash-requests")
    monkeypatch.setattr(h, "_sqs_client", lambda: sqs)
    return sqs


def _post(route, body, token=None):
    ev = {"routeKey": route, "body": json.dumps(body)}
    if token is not None:
        ev["headers"] = {"X-Leash-Token": token}  # API Gateway lowercases, but be case-insensitive anyway
    return h.handler(ev, None)


def test_routes_are_open_when_no_token_is_configured(worker_mode, monkeypatch):
    """Local demo and tests: no token. A deployment cannot get here (the parameter is mandatory)."""
    monkeypatch.delenv("OPERATOR_TOKEN", raising=False)
    resp = _post("POST /redteam", {"n": 5})
    assert resp["statusCode"] == 202 and worker_mode.sent[0]["kind"] == "redteam"


def test_redteam_launch_needs_the_right_token(worker_mode, monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", "s3cret")
    assert _post("POST /redteam", {"n": 5})["statusCode"] == 401
    assert _post("POST /redteam", {"n": 5}, token="wrong")["statusCode"] == 401
    assert worker_mode.sent == []
    resp = _post("POST /redteam", {"n": 5}, token="s3cret")
    assert resp["statusCode"] == 202 and worker_mode.sent[0]["kind"] == "redteam"


def test_approve_needs_the_token(monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", "s3cret")
    called = []
    import common.proposals as proposals

    monkeypatch.setattr(proposals, "approve", lambda pid: called.append(pid) or {"id": pid})
    assert _post("POST /policies/approve", {"id": "proposal-1"})["statusCode"] == 401
    assert called == []
    assert _post("POST /policies/approve", {"id": "proposal-1"}, token="s3cret")["statusCode"] == 200
    assert called == ["proposal-1"]


def test_ask_and_reads_never_need_the_token(worker_mode, monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", "s3cret")
    assert _post("POST /ask", {"message": "terminate i-1"})["statusCode"] == 202
    assert h.handler({"routeKey": "GET /health"}, None)["statusCode"] == 200
    assert "x-leash-token" in h.CORS_HEADERS["Access-Control-Allow-Headers"]
