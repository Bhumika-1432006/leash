"""Authorisation for every Leash action: ask Cedar before touching anything.

Three backends, same request, same Decision:

  LEASH_AUTHZ_FUNCTION=<name>   invoke the Leash authorizer Lambda (src/authz_service). It holds
                                the policies (S3) and writes the audit row before answering. This
                                is the Free-plan path and the strictest one: the caller never
                                sees policy text and cannot skip the audit.
  LEASH_LOCAL_AUTHZ=1           evaluate with cedarpy right here, from cedar/ on disk or from the
                                S3 bucket in LEASH_CEDAR_S3_BUCKET (the authorizer Lambda itself,
                                the API's /policies, tests, the offline demo).
  otherwise                     Amazon Verified Permissions (IsAuthorized) on POLICY_STORE_ID.

Any failure is a DENY ("authz-error: ...").
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

NAMESPACE = "Leash"
PRINCIPAL_ID = "leash"
RESOURCE_TYPES = ("Instance", "EcsService", "AutoScalingGroup")
POLICY_NAMES = ("PermitDevRemediation", "ForbidDestructive", "ForbidProd", "ForbidScaleAboveCap")

_AVP = None  # cached boto3 client
_LAMBDA = None  # cached boto3 client for the authorizer function
_LOCAL: dict = {}  # cached cedarpy inputs: {"policies", "schema", "dir" | "etag", "version"}
_S3: dict = {}  # cached policy texts from S3: {"etag": ..., "files": {name: text}, "version": ...}
_AUDIT_CTX = {"incident_id": "unset", "alarm_name": ""}  # sent along to the authorizer Lambda


def set_audit_context(incident_id: str, alarm_name: str = "") -> None:
    """The authorizer Lambda writes the audit row itself, so it needs to know the incident."""
    _AUDIT_CTX["incident_id"] = incident_id
    _AUDIT_CTX["alarm_name"] = alarm_name


@dataclass
class Decision:
    """Outcome of one authorisation request (allowed, which policies decided, why)."""

    allowed: bool
    policy_ids: list = field(default_factory=list)
    reason: str = ""
    errors: list = field(default_factory=list)
    # Set when the authorizer service already wrote the audit row: {"pk", "sk"}. The tool then
    # only reports its result into that row instead of writing a second one.
    audit_ref: dict | None = None


def authorize(action: str, resource_type: str, resource_id: str, resource_env: str,
              context: dict | None = None) -> Decision:
    """Is Leash::Agent::"leash" allowed to perform `action` on this resource?

    resource_type is "Instance" | "EcsService" | "AutoScalingGroup" (no namespace).
    Fails closed: any exception becomes Decision(allowed=False, reason="authz-error: ...").
    """
    try:
        if resource_type not in RESOURCE_TYPES:
            raise ValueError(f"unknown resource_type {resource_type!r}")
        if os.environ.get("LEASH_AUTHZ_FUNCTION"):
            return _authorize_lambda(action, resource_type, resource_id, resource_env, context or {})
        if os.environ.get("LEASH_LOCAL_AUTHZ") == "1":
            return _authorize_local(action, resource_type, resource_id, resource_env, context or {})
        return _authorize_avp(action, resource_type, resource_id, resource_env, context or {})
    except Exception as exc:  # noqa: BLE001 - fail closed, whatever went wrong
        return Decision(allowed=False, policy_ids=[], reason=f"authz-error: {exc}", errors=[str(exc)])


def evaluate_local(action, resource_type, resource_id, resource_env, context) -> Decision:
    """Public entry for the authorizer Lambda: cedarpy evaluation, fail closed."""
    try:
        if resource_type not in RESOURCE_TYPES:
            raise ValueError(f"unknown resource_type {resource_type!r}")
        return _authorize_local(action, resource_type, resource_id, resource_env, context or {})
    except Exception as exc:  # noqa: BLE001
        return Decision(allowed=False, policy_ids=[], reason=f"authz-error: {exc}", errors=[str(exc)])


# --- the authorizer Lambda ----------------------------------------------------------


def _lambda_client():
    global _LAMBDA
    if _LAMBDA is None:
        import boto3

        _LAMBDA = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _LAMBDA


def _invoke_authz(payload: dict) -> dict:
    resp = _lambda_client().invoke(
        FunctionName=os.environ["LEASH_AUTHZ_FUNCTION"], InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    data = json.loads(resp["Payload"].read() or b"{}")
    if resp.get("FunctionError") or (isinstance(data, dict) and data.get("error")):
        raise RuntimeError(f"authorizer failed: {data.get('error') if isinstance(data, dict) else data}")
    return data


def _authorize_lambda(action, resource_type, resource_id, resource_env, context) -> Decision:
    data = _invoke_authz({
        "op": "authorize", "action": action, "resource_type": resource_type, "resource_id": resource_id,
        "resource_env": resource_env, "context": context or None,
        "incident_id": _AUDIT_CTX["incident_id"], "alarm_name": _AUDIT_CTX["alarm_name"],
    })
    return Decision(allowed=bool(data.get("allowed")), policy_ids=list(data.get("policy_ids") or []),
                    reason=str(data.get("reason", "")), errors=list(data.get("errors") or []),
                    audit_ref=data.get("audit_ref") or None)


# --- Amazon Verified Permissions ------------------------------------------------


def _avp_client():
    global _AVP
    if _AVP is None:
        import boto3

        _AVP = boto3.client("verifiedpermissions", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _AVP


def _avp_value(value):
    """Type a Python value the way the Verified Permissions API wants it ({"long": 4} etc.)."""
    if isinstance(value, bool):
        return {"boolean": value}
    if isinstance(value, int):
        return {"long": value}
    if isinstance(value, str):
        return {"string": value}
    raise TypeError(f"unsupported context value type {type(value).__name__}")


def _policy_names() -> dict:
    """AVP policy id -> logical name, from POLICY_ID_MAP (cedar/template.yaml output PolicyIdMap)."""
    raw = os.environ.get("POLICY_ID_MAP", "")
    if not raw:
        return {}
    return {pid: name for name, pid in json.loads(raw).items()}


def _authorize_avp(action, resource_type, resource_id, resource_env, context) -> Decision:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/verifiedpermissions/client/is_authorized.html
    entity_type = f"{NAMESPACE}::{resource_type}"
    resp = _avp_client().is_authorized(
        policyStoreId=os.environ["POLICY_STORE_ID"],
        principal={"entityType": f"{NAMESPACE}::Agent", "entityId": PRINCIPAL_ID},
        action={"actionType": f"{NAMESPACE}::Action", "actionId": action},
        resource={"entityType": entity_type, "entityId": resource_id},
        context={"contextMap": {k: _avp_value(v) for k, v in context.items()}},
        entities={"entityList": [
            {"identifier": {"entityType": f"{NAMESPACE}::Agent", "entityId": PRINCIPAL_ID},
             "attributes": {}, "parents": []},
            {"identifier": {"entityType": entity_type, "entityId": resource_id},
             "attributes": {"env": {"string": resource_env}}, "parents": []},
        ]},
    )
    names = _policy_names()
    raw_ids = [p.get("policyId", "") for p in resp.get("determiningPolicies", [])]
    policy_ids = [names.get(pid, pid) for pid in raw_ids]
    errors = [e.get("errorDescription", "") for e in resp.get("errors", [])]
    allowed = resp.get("decision") == "ALLOW"
    return Decision(allowed=allowed, policy_ids=policy_ids, reason=_reason(allowed, policy_ids, "avp"), errors=errors)


# --- local evaluation with cedarpy --------------------------------------------------


def reset_cache() -> None:
    _LOCAL.clear()
    _S3.clear()


def cedar_dir() -> Path:
    """cedar/ directory: LEASH_CEDAR_DIR, else the repo's cedar/ next to src/."""
    override = os.environ.get("LEASH_CEDAR_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "cedar"


def _policy_files() -> tuple[dict, str]:
    """{name: text} for the policies plus 'schema', and a version string, from S3 or disk."""
    bucket = os.environ.get("LEASH_CEDAR_S3_BUCKET")
    if bucket:
        return _policy_files_s3(bucket)
    base = cedar_dir()
    # Every policy in the store, not a fixed list: a policy approved from a proposal (#21) is a
    # new file next to the four canonical ones and must be enforced without a code change.
    files = {path.stem: path.read_text(encoding="utf-8") for path in sorted((base / "policies").glob("*.cedar"))}
    files["schema"] = (base / "schema.json").read_text(encoding="utf-8")
    # Same role as the S3 ETag version: identifies the policy set in force and changes the
    # moment any policy text changes. A content hash, not a path, so it is stable and
    # does not leak the machine's directory layout onto the dashboard.
    import hashlib

    digest = hashlib.sha256("".join(files[k] for k in sorted(files)).encode("utf-8")).hexdigest()[:8]
    return files, f"disk:{digest}"


def _policy_files_s3(bucket: str) -> tuple[dict, str]:
    """Policies from s3://bucket/cedar/. One ListObjects per call detects a change (ETags), so an
    edited policy is live on the next decision without a redeploy."""
    import boto3

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="cedar/")
    etags = {o["Key"]: o["ETag"] for o in listing.get("Contents", [])}
    version = "s3:" + ",".join(f"{k}={v.strip(chr(34))[:8]}" for k, v in sorted(etags.items()))
    if _S3.get("version") != version:
        files = {}
        for key in sorted(etags):
            if key.startswith("cedar/policies/") and key.endswith(".cedar"):
                name = key[len("cedar/policies/"):-len(".cedar")]
                files[name] = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        files["schema"] = s3.get_object(Bucket=bucket, Key="cedar/schema.json")["Body"].read().decode("utf-8")
        _S3.update(version=version, files=files)
    return _S3["files"], _S3["version"]


def policy_version() -> str:
    """Identifies the policy set currently in force (S3 ETags or the disk path)."""
    try:
        return _policy_files()[1]
    except Exception as exc:  # noqa: BLE001
        return f"unknown: {exc}"


def policy_names(files: dict) -> list[str]:
    """The canonical four first, then any others in the store, alphabetically."""
    extra = sorted(n for n in files if n != "schema" and n not in POLICY_NAMES)
    return [n for n in POLICY_NAMES if n in files] + extra


def _load_local() -> dict:
    """Cedarpy inputs (policies with an @id each so diagnostics name them, and the schema),
    rebuilt whenever the policy set version changes."""
    files, version = _policy_files()
    if _LOCAL.get("version") != version:
        parts = [f'@id("{name}")\n{files[name]}' for name in policy_names(files)]
        _LOCAL.update(version=version, policies="\n".join(parts), schema=json.loads(files["schema"]))
    return _LOCAL


def _authorize_local(action, resource_type, resource_id, resource_env, context) -> Decision:
    # cedarpy 4.x: is_authorized(request, policies, entities, schema) -> AuthzResult;
    # diagnostics.reasons are parser ids ("policy0"), id_annotations_by_reason maps them to @id.
    import cedarpy

    local = _load_local()
    entity_type = f"{NAMESPACE}::{resource_type}"
    request = {
        "principal": {"type": f"{NAMESPACE}::Agent", "id": PRINCIPAL_ID},
        "action": {"type": f"{NAMESPACE}::Action", "id": action},
        "resource": {"type": entity_type, "id": resource_id},
        "context": dict(context),
    }
    entities = [
        {"uid": {"type": f"{NAMESPACE}::Agent", "id": PRINCIPAL_ID}, "attrs": {}, "parents": []},
        {"uid": {"type": entity_type, "id": resource_id}, "attrs": {"env": resource_env}, "parents": []},
    ]
    result = cedarpy.is_authorized(request, local["policies"], entities, local["schema"])
    names = result.diagnostics.id_annotations_by_reason
    policy_ids = [names.get(r, r) for r in result.diagnostics.reasons]
    allowed = result.allowed
    return Decision(allowed=allowed, policy_ids=policy_ids, reason=_reason(allowed, policy_ids, "local"),
                    errors=list(result.diagnostics.errors))


# --- the leash, readable ---------------------------------------------------------------


def list_policies() -> list[dict]:
    """Every policy in the store as [{"id", "effect", "description", "statement"}], in POLICY_NAMES
    order, so the dashboard can show the leash next to the audit trail.

    Same switch as authorize(): LEASH_LOCAL_AUTHZ=1 reads cedar/policies/*.cedar, otherwise the
    text comes from Verified Permissions itself (ListPolicies + GetPolicy), so what is shown is
    what is enforced. Failures raise; the API turns them into a 500 with the message.
    """
    return list_policies_with_version()[0]


def list_policies_with_version() -> tuple[list[dict], str]:
    """(rows, version): version identifies the policy set in force (S3 ETags, disk path, or
    'avp' for a managed store), so a dashboard can show that a hot-reloaded edit is live."""
    if os.environ.get("LEASH_AUTHZ_FUNCTION"):
        data = _invoke_authz({"op": "list_policies"})
        return list(data.get("items") or []), str(data.get("policy_version", "unknown"))
    if os.environ.get("LEASH_LOCAL_AUTHZ") == "1":
        files, version = _policy_files()
        return [_policy_row(name, files[name], "") for name in policy_names(files)], version
    return _list_policies_avp(), "avp"


def _policy_row(name: str, statement: str, description: str) -> dict:
    return {"id": name, "effect": "forbid" if statement.lstrip().startswith("forbid") else "permit",
            "description": description, "statement": statement.strip()}


def _list_policies_avp() -> list[dict]:
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/verifiedpermissions/client/list_policies.html
    store = os.environ["POLICY_STORE_ID"]
    names = _policy_names()
    rows = {}
    for item in _avp_client().list_policies(policyStoreId=store).get("policies", []):
        pid = item.get("policyId", "")
        # ListPolicies carries the description; the statement text needs GetPolicy.
        full = _avp_client().get_policy(policyStoreId=store, policyId=pid)
        static = (full.get("definition") or {}).get("static") or {}
        name = names.get(pid, pid)
        rows[name] = _policy_row(name, static.get("statement", ""), static.get("description", ""))
    ordered = [rows[n] for n in POLICY_NAMES if n in rows]
    return ordered + [rows[n] for n in rows if n not in POLICY_NAMES]


def _reason(allowed: bool, policy_ids: list, mode: str) -> str:
    if allowed:
        return f"permit by {', '.join(policy_ids)} ({mode})"
    if policy_ids:
        return f"forbid by {', '.join(policy_ids)} ({mode})"
    return f"no permit policy matched; Cedar denies by default ({mode})"
