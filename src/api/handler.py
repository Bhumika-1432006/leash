"""Leash API Lambda.

Serves three HTTP API (payload format v2) routes behind API Gateway:

    GET  /health        -> {"ok": true}
    GET  /audit?limit=N -> {"items": [...]}   (newest first, via common.audit.list_audit)
    GET  /policies      -> {"items": [...]}   (the Cedar policies, via common.authz.list_policies)
    GET  /redteam       -> {"items": [...], "summary": {...}}  (attack rows + the numbers)
    POST /redteam       -> {"run_id": ...}   starts an attack run on the red-team Lambda (async)
    POST /ask           -> Bedrock mode: invokes the agent Lambda synchronously and returns its
                           reply. Worker mode (REQUEST_QUEUE_URL set): queues the request and
                           returns 202 {"incident_id"}; the reply arrives via GET /reply.
    GET  /reply?incident_id=X -> {"reply": ...} once the worker has answered, else 202 pending

Every response carries permissive CORS headers so the static dashboard on S3 can call it.
Routing uses event["routeKey"] ("GET /audit"), which is how HTTP API v2 events identify the
matched route. See https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
"""

import base64
import json
import os

import boto3

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Content-Type": "application/json",
}

MAX_MESSAGE_CHARS = 2000
MAX_AUDIT_LIMIT = 200

_lambda = None
_sqs = None


def _sqs_client():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client("sqs")
    return _sqs


def _queue(kind: str, payload: dict) -> None:
    _sqs_client().send_message(QueueUrl=os.environ["REQUEST_QUEUE_URL"],
                               MessageBody=json.dumps({"kind": kind, **payload}))


def _lambda_client():
    """Return a cached boto3 Lambda client (created lazily so tests can swap it out)."""
    global _lambda
    if _lambda is None:
        _lambda = boto3.client("lambda")
    return _lambda


def _response(status: int, body) -> dict:
    """Build an HTTP API v2 response with CORS headers and a JSON body."""
    return {"statusCode": status, "headers": dict(CORS_HEADERS), "body": json.dumps(body, default=str)}


def _error(status: int, message: str) -> dict:
    return _response(status, {"error": message})


def _read_body(event: dict):
    """Decode the request body (base64 if flagged) and parse it as a JSON object."""
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    return data


HEARTBEAT_STALE_S = 90


def _health(event: dict) -> dict:
    """{"ok": true, "brain": {...}}: in worker mode, whether the brain has been seen recently."""
    body = {"ok": True}
    if os.environ.get("REQUEST_QUEUE_URL"):
        from datetime import datetime, timezone

        from common.audit import read_heartbeat

        brain = {"mode": "worker", "online": False}
        try:
            hb = read_heartbeat()
        except Exception as exc:  # noqa: BLE001 - health must not fail on a missing row
            hb, brain["error"] = None, str(exc)
        if hb:
            seen = datetime.strptime(hb["at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - seen).total_seconds()
            brain.update(online=age < HEARTBEAT_STALE_S, seen=hb["at"], age_s=int(age),
                         model=hb.get("model", ""), host=hb.get("host", ""))
        body["brain"] = brain
    elif os.environ.get("LEASH_LOCAL_MODEL") == "1":
        # local_demo: the agent runs in this process on a local model (or the scripted stand-in).
        body["brain"] = {"mode": "local", "online": True,
                         "model": "scripted" if os.environ.get("LEASH_SCRIPTED_AGENT") == "1"
                         else os.environ.get("OLLAMA_MODEL_ID", "local model")}
    else:
        body["brain"] = {"mode": "bedrock", "online": True}
    return _response(200, body)


def _audit(event: dict) -> dict:
    """List recent audit rows. Imported lazily so tests can monkeypatch common.audit."""
    from common.audit import list_audit

    params = event.get("queryStringParameters") or {}
    try:
        limit = int(params.get("limit", 50))
    except (TypeError, ValueError):
        return _error(400, "limit must be an integer")
    limit = max(1, min(limit, MAX_AUDIT_LIMIT))
    return _response(200, {"items": list_audit(limit=limit)})


def _policies(event: dict) -> dict:
    """The leash itself: every Cedar policy with its text, read from the same backend that
    enforces it (Verified Permissions in the cloud, the .cedar files in the local demo)."""
    from common.authz import list_policies_with_version

    items, version = list_policies_with_version()
    return _response(200, {"items": items, "policy_version": version})


def _redteam_get(event: dict) -> dict:
    """Attack rows newest first plus the computed headline numbers."""
    from common.audit import list_redteam
    from redteam.runner import summarise

    params = event.get("queryStringParameters") or {}
    try:
        limit = int(params.get("limit", 200))
    except (TypeError, ValueError):
        return _error(400, "limit must be an integer")
    rows = list_redteam(limit=max(1, min(limit, 500)))
    run = str(params.get("run") or "all")
    if run == "latest" and rows:
        latest = max(r.get("run_id", "") for r in rows)
        rows = [r for r in rows if r.get("run_id") == latest]
    elif run not in ("all", ""):
        rows = [r for r in rows if r.get("run_id") == run]
    return _response(200, {"items": rows, "summary": summarise(rows), "run": run})


MAX_REDTEAM_N = 100


def _redteam_post(event: dict) -> dict:
    """Kick off a run: n attacks, both arms by default. Returns immediately; rows stream in."""
    try:
        body = _read_body(event)
    except (ValueError, UnicodeDecodeError) as exc:
        return _error(400, f"invalid JSON body: {exc}")
    try:
        n = int(body.get("n", 20))
    except (TypeError, ValueError):
        return _error(400, "'n' must be an integer")
    n = max(1, min(n, MAX_REDTEAM_N))
    arms = body.get("arms") or ["leashed", "unleashed"]
    if not isinstance(arms, list) or not set(arms) <= {"leashed", "unleashed"}:
        return _error(400, "'arms' must be a list of 'leashed' and/or 'unleashed'")
    from redteam.runner import _now_id

    run_id = _now_id()
    payload = {"n": n, "arms": arms, "run_id": run_id, "use_model": bool(body.get("use_model", True))}
    if os.environ.get("REQUEST_QUEUE_URL"):
        _queue("redteam", payload)
        return _response(202, {"run_id": run_id, "n": n, "arms": arms, "status": "queued"})
    function_name = os.environ.get("REDTEAM_FUNCTION_NAME")
    if not function_name:
        return _error(500, "REDTEAM_FUNCTION_NAME is not configured")
    _lambda_client().invoke(FunctionName=function_name, InvocationType="Event",
                            Payload=json.dumps(payload).encode("utf-8"))
    return _response(202, {"run_id": run_id, "n": n, "arms": arms})


def _reply(event: dict) -> dict:
    from common.audit import get_reply

    params = event.get("queryStringParameters") or {}
    incident_id = str(params.get("incident_id") or "").strip()
    if not incident_id:
        return _error(400, "incident_id is required")
    row = get_reply(incident_id)
    if not row:
        return _response(202, {"incident_id": incident_id, "status": "pending"})
    return _response(200, {"incident_id": incident_id, "reply": row.get("reply", ""), "at": row.get("at", "")})


def _ask(event: dict) -> dict:
    """Forward a human question to the agent Lambda and relay its reply."""
    try:
        body = _read_body(event)
    except (ValueError, UnicodeDecodeError) as exc:
        return _error(400, f"invalid JSON body: {exc}")

    message = body.get("message")
    if not isinstance(message, str) or not message.strip():
        return _error(400, "'message' (non-empty string) is required")
    if len(message) > MAX_MESSAGE_CHARS:
        return _error(400, f"message longer than {MAX_MESSAGE_CHARS} characters")

    if os.environ.get("REQUEST_QUEUE_URL"):
        from common.audit import timestamp

        incident_id = "chat-" + timestamp().replace("-", "").replace(":", "").split(".")[0] + "Z"
        _queue("chat", {"incident_id": incident_id, "message": message.strip()})
        return _response(202, {"incident_id": incident_id, "status": "queued"})

    function_name = os.environ.get("AGENT_FUNCTION_NAME")
    if not function_name:
        return _error(500, "AGENT_FUNCTION_NAME is not configured")

    payload = json.dumps({"mode": "chat", "message": message.strip()})
    # Synchronous invoke: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda/client/invoke.html
    resp = _lambda_client().invoke(
        FunctionName=function_name, InvocationType="RequestResponse", Payload=payload.encode("utf-8")
    )
    raw = resp["Payload"].read()
    try:
        result = json.loads(raw or b"{}")
    except ValueError:
        return _error(502, "agent returned a non-JSON payload")
    if resp.get("FunctionError"):
        detail = result.get("errorMessage") if isinstance(result, dict) else str(result)
        return _error(502, f"agent failed: {detail}")
    if not isinstance(result, dict):
        result = {"reply": str(result)}
    return _response(200, result)


def _propose(event: dict) -> dict:
    """English -> Cedar (#21). Drafts, validates, proves, stores. Never publishes.

    Worker mode: queued to the brain (it has the model); the row appears in GET /policies/proposals.
    Otherwise: runs here, with the model if one is configured, else the template drafter."""
    try:
        body = _read_body(event)
    except (ValueError, UnicodeDecodeError) as exc:
        return _error(400, f"invalid JSON body: {exc}")
    text = body.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error(400, "'text' (non-empty string) is required")
    from common.proposals import MAX_TEXT

    if len(text) > MAX_TEXT:
        return _error(400, f"text longer than {MAX_TEXT} characters")
    if os.environ.get("REQUEST_QUEUE_URL"):
        _queue("propose", {"text": text.strip()})
        return _response(202, {"status": "queued", "text": text.strip()})
    from common.proposals import propose

    try:
        from agent.agent import drafter_or_none

        drafter = drafter_or_none()
    except Exception:  # noqa: BLE001 - no model stack in this process: template drafting only
        drafter = None
    return _response(200, propose(text, drafter=drafter))


def _proposals(event: dict) -> dict:
    from common.proposals import list_proposals

    params = event.get("queryStringParameters") or {}
    try:
        limit = int(params.get("limit", 20))
    except (TypeError, ValueError):
        return _error(400, "limit must be an integer")
    return _response(200, {"items": list_proposals(limit=max(1, min(limit, 100)))})


def _approve(event: dict) -> dict:
    """The only path that publishes a policy. A person clicked Approve on a proposal Cedar accepted."""
    try:
        body = _read_body(event)
    except (ValueError, UnicodeDecodeError) as exc:
        return _error(400, f"invalid JSON body: {exc}")
    pid = body.get("id")
    if not isinstance(pid, str) or not pid.startswith("proposal-"):
        return _error(400, "'id' (a proposal id) is required")
    from common.proposals import approve

    try:
        return _response(200, approve(pid))
    except LookupError as exc:
        return _error(404, str(exc))
    except ValueError as exc:
        return _error(409, str(exc))


ROUTES = {
    "POST /policies/propose": _propose,
    "GET /policies/proposals": _proposals,
    "POST /policies/approve": _approve,
    "GET /health": _health,
    "GET /audit": _audit,
    "GET /policies": _policies,
    "GET /redteam": _redteam_get,
    "GET /reply": _reply,
    "POST /redteam": _redteam_post,
    "POST /ask": _ask,
}


def handler(event, context):
    """Lambda entry point. Routes by HTTP API v2 routeKey; never raises to the caller."""
    route = event.get("routeKey")
    if not route:  # tolerate a hand-built event without routeKey
        http = (event.get("requestContext") or {}).get("http") or {}
        route = f"{http.get('method', '')} {event.get('rawPath', '')}".strip()
    if route.startswith("OPTIONS"):
        return _response(204, {})
    fn = ROUTES.get(route)
    if fn is None:
        return _error(404, f"unknown route: {route}")
    try:
        return fn(event)
    except Exception as exc:  # noqa: BLE001 - surface any failure as JSON, keep CORS headers
        return _error(500, f"{type(exc).__name__}: {exc}")
