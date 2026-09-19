"""English -> Cedar, proven before it is published (issue #21).

    propose(text)          draft a policy from a sentence, validate it against cedar/schema.json,
                           prove what it would change, store the proposal. Never publishes.
    approve(proposal_id)   the ONLY path that writes a policy to the store (S3 bucket, or the
                           cedar/ directory the local demo was pointed at). A human clicks it.

Drafting has two layers. A template drafter handles the phrasings an operator actually uses
("never scale above 2", "never touch prod", "the bot may never restart anything") with no model
at all, so the feature works in CI and the scripted local demo. When a model is available
(`drafter=` callable) it is asked first, against the schema and the current policies, and its
answer is used only if Cedar accepts it; otherwise the template draft is used and the proposal
says so. The model drafts; Cedar decides whether the draft is even valid; a person approves.

"Prove it" means: evaluate a fixed set of requests against the current policies and against the
current policies plus the candidate, and report every request whose answer changes. A rule that
changes nothing is probably redundant; a rule that flips "clean the dev disk" to DENY is probably
wrong. Either way the person approving sees it before the click.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field

from common import audit, authz

PARTITION = "PROPOSAL"
MAX_TEXT = 500

ACTIONS = ("cleanDisk", "restartService", "scaleGroup", "terminateInstance", "deleteResource")
VERBS = {  # words a person uses -> the Cedar action name
    "cleanDisk": ("clean", "cleanup", "clean up", "free disk", "free up"),
    "restartService": ("restart", "redeploy", "force new deployment", "bounce"),
    "scaleGroup": ("scale", "resize", "grow", "shrink"),
    "terminateInstance": ("terminate", "kill", "shut down", "shutdown"),
    "deleteResource": ("delete", "destroy", "remove"),
}

# The proof set. Same request shape as authz._authorize_local; env and context matter.
PROOF_CASES = [
    ("clean the dev disk", "cleanDisk", "Instance", "i-dev", "dev", {}),
    ("restart the dev service", "restartService", "EcsService", "leash-dev/leash-api-dev", "dev", {}),
    ("scale dev to 2", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": 2}),
    ("scale dev to 4", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": 4}),
    ("scale dev to 6", "scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": 6}),
    ("terminate the dev instance", "terminateInstance", "Instance", "i-dev", "dev", {}),
    ("clean the prod disk", "cleanDisk", "Instance", "i-prod", "prod", {}),
    ("restart the prod service", "restartService", "EcsService", "leash-prod/db", "prod", {}),
    ("terminate the prod instance", "terminateInstance", "Instance", "i-prod", "prod", {}),
    ("clean an untagged disk", "cleanDisk", "Instance", "i-unknown", "unknown", {}),
    ("clean a staging disk", "cleanDisk", "Instance", "i-staging", "staging", {}),
]


@dataclass
class Draft:
    name: str
    statement: str
    source: str  # "template" | "model" | "model (rejected) -> template"
    note: str = ""


@dataclass
class Validation:
    ok: bool
    errors: list = field(default_factory=list)


# --- drafting -------------------------------------------------------------------------------


def _action_in(text: str) -> str | None:
    low = text.lower()
    for action, words in VERBS.items():
        if any(w in low for w in words):
            return action
    return None


def _env_in(text: str) -> str | None:
    m = re.search(r"\b(prod|production|dev|staging|test)\b", text.lower())
    if not m:
        return None
    return {"production": "prod"}.get(m.group(1), m.group(1))


def _number_in(text: str) -> int | None:
    m = re.search(r"\b(?:above|over|more than|past|beyond|to|at)\s+(\d{1,3})\b", text.lower())
    return int(m.group(1)) if m else None


def template_draft(text: str) -> Draft | None:
    """Cedar for the sentences an operator actually types. None if no template fits."""
    low = text.lower().strip()
    forbid = bool(re.search(r"\b(never|must not|may not|can(?:no|')t|forbid|don'?t|do not|not allowed)\b", low))
    permit = bool(re.search(r"\b(may|can|allow|allowed|permit|let)\b", low)) and not forbid
    action = _action_in(low)
    env = _env_in(low)
    n = _number_in(low)

    if forbid and action == "scaleGroup" and n is not None:
        return Draft("ForbidScaleAboveCap",
                     "forbid (\n    principal,\n    action == Leash::Action::\"scaleGroup\",\n    resource\n"
                     f") when {{ context.desiredCapacity > {n} }};\n",
                     "template", f"replaces the current scale cap with {n}")
    if forbid and env and not action:
        name = "ForbidProd" if env == "prod" else f"Forbid{env.capitalize()}"
        return Draft(name,
                     f"forbid (principal, action, resource) when {{ resource.env == \"{env}\" }};\n",
                     "template", f"no action at all on anything tagged env={env}")
    if forbid and action and env:
        return Draft(f"Forbid{action[0].upper()}{action[1:]}On{env.capitalize()}",
                     f"forbid (\n    principal,\n    action == Leash::Action::\"{action}\",\n    resource\n"
                     f") when {{ resource.env == \"{env}\" }};\n",
                     "template", f"{action} is refused on env={env}")
    if forbid and action:
        return Draft(f"Forbid{action[0].upper()}{action[1:]}",
                     f"forbid (\n    principal,\n    action == Leash::Action::\"{action}\",\n    resource\n);\n",
                     "template", f"{action} is refused everywhere")
    if permit and action and env:
        return Draft(f"Permit{action[0].upper()}{action[1:]}On{env.capitalize()}",
                     "permit (\n    principal == Leash::Agent::\"leash\",\n"
                     f"    action == Leash::Action::\"{action}\",\n    resource\n"
                     f") when {{ resource.env == \"{env}\" }};\n",
                     "template", f"{action} is permitted on env={env} (a forbid still wins)")
    return None


MODEL_PROMPT = """You write Cedar policies for an ops agent. Output ONLY one Cedar policy statement, no prose, no code fences.

Schema (Cedar JSON):
{schema}

Policies already in force:
{policies}

The principal is always Leash::Agent::"leash". Actions are Leash::Action::"cleanDisk", "restartService", "scaleGroup", "terminateInstance", "deleteResource". Resources have an attribute env (a string). scaleGroup carries context.desiredCapacity (a Long).

Write one policy that implements exactly this rule and nothing more:
{text}
"""


def model_draft(text: str, drafter, files: dict) -> str:
    """Ask a model; return raw text (caller validates). `drafter(prompt) -> str`."""
    policies = "\n\n".join(files[n] for n in authz.policy_names(files))
    raw = str(drafter(MODEL_PROMPT.format(schema=files["schema"], policies=policies, text=text))).strip()
    raw = re.sub(r"^```(?:cedar)?\s*|\s*```$", "", raw).strip()
    return raw


def _name_for(statement: str, text: str) -> str:
    """A CamelCase name for a model-written policy, from the sentence."""
    words = re.findall(r"[a-z0-9]+", text.lower())[:6]
    base = "".join(w.capitalize() for w in words) or "Proposed"
    effect = "Forbid" if statement.lstrip().startswith("forbid") else "Permit"
    return f"{effect}{base}"[:48]


# --- validation and proof --------------------------------------------------------------------


def validate(statement: str, schema: dict) -> Validation:
    import cedarpy

    try:
        res = cedarpy.validate_policies(statement, schema)
    except Exception as exc:  # noqa: BLE001 - a parse failure is a validation failure
        return Validation(False, [str(exc)])
    return Validation(bool(res.validation_passed), [str(e) for e in res.errors])


def _decide(policies_text: str, schema: dict, action, rtype, rid, env, context) -> tuple[bool, list]:
    import cedarpy

    entity_type = f"{authz.NAMESPACE}::{rtype}"
    request = {"principal": {"type": f"{authz.NAMESPACE}::Agent", "id": authz.PRINCIPAL_ID},
               "action": {"type": f"{authz.NAMESPACE}::Action", "id": action},
               "resource": {"type": entity_type, "id": rid}, "context": dict(context)}
    entities = [{"uid": {"type": f"{authz.NAMESPACE}::Agent", "id": authz.PRINCIPAL_ID}, "attrs": {}, "parents": []},
                {"uid": {"type": entity_type, "id": rid}, "attrs": {"env": env}, "parents": []}]
    res = cedarpy.is_authorized(request, policies_text, entities, schema)
    names = res.diagnostics.id_annotations_by_reason
    return bool(res.allowed), [names.get(r, r) for r in res.diagnostics.reasons]


def prove(name: str, statement: str, files: dict) -> dict:
    """Every proof case before and after the candidate; `changed` lists the flips."""
    schema = json.loads(files["schema"])
    current = {n: files[n] for n in authz.policy_names(files)}
    after = dict(current)
    after[name] = statement  # replaces a same-named policy, otherwise adds
    before_text = "\n".join(f'@id("{n}")\n{t}' for n, t in current.items())
    after_text = "\n".join(f'@id("{n}")\n{t}' for n, t in after.items())
    rows, changed = [], []
    for label, action, rtype, rid, env, ctx in PROOF_CASES:
        b_ok, b_ids = _decide(before_text, schema, action, rtype, rid, env, ctx)
        a_ok, a_ids = _decide(after_text, schema, action, rtype, rid, env, ctx)
        row = {"case": label, "before": "ALLOW" if b_ok else "DENY", "after": "ALLOW" if a_ok else "DENY",
               "before_policies": b_ids, "after_policies": a_ids, "changed": b_ok != a_ok}
        rows.append(row)
        if b_ok != a_ok:
            changed.append(f"{label}: {row['before']} -> {row['after']}")
    return {"cases": rows, "changed": changed, "replaces": name in current}


# --- the two entry points --------------------------------------------------------------------


def propose(text: str, drafter=None) -> dict:
    """Draft, validate, prove, store. Never writes a policy anywhere."""
    text = str(text or "").strip()
    if not text:
        raise ValueError("text is required")
    if len(text) > MAX_TEXT:
        raise ValueError(f"text longer than {MAX_TEXT} characters")
    files, version = authz._policy_files()
    schema = json.loads(files["schema"])

    draft = template_draft(text)
    if drafter is not None:
        try:
            raw = model_draft(text, drafter, files)
            v = validate(raw, schema)
            if v.ok and raw:
                draft = Draft(draft.name if draft else _name_for(raw, text), raw if raw.endswith("\n") else raw + "\n",
                              "model", "written by the model, accepted by Cedar")
            elif draft:
                draft.source = "model (rejected) -> template"
                draft.note = f"model draft rejected by Cedar ({'; '.join(v.errors)[:200] or 'empty'}); template used"
            else:
                draft = Draft(_name_for(raw or "forbid", text), raw or "", "model (rejected)",
                              f"rejected by Cedar: {'; '.join(v.errors)[:300] or 'empty output'}")
        except Exception as exc:  # noqa: BLE001 - a model failure must not lose the template path
            if draft:
                draft.source = "model (failed) -> template"
                draft.note = f"model unavailable ({exc}); template used"
            else:
                draft = Draft("Proposed", "", "model (failed)", f"model unavailable ({exc}) and no template fits")
    if draft is None:
        draft = Draft("Proposed", "", "none", "no template fits this sentence and no model was available")

    validation = validate(draft.statement, schema) if draft.statement else Validation(False, ["empty draft"])
    proof = prove(draft.name, draft.statement, files) if validation.ok else {"cases": [], "changed": [], "replaces": False}

    pk = "proposal-" + audit.timestamp().replace("-", "").replace(":", "").replace(".", "")[:21]
    row = audit.write_generic(pk, PARTITION, {
        "text": text, "name": draft.name, "statement": draft.statement, "source": draft.source, "note": draft.note,
        "valid": "true" if validation.ok else "false", "errors": validation.errors,
        "changed": proof["changed"], "replaces": "true" if proof["replaces"] else "false",
        "cases": json.dumps(proof["cases"]), "status": "proposed", "policy_version_at_draft": version,
    })
    row["cases"] = proof["cases"]
    return row


def list_proposals(limit: int = 20) -> list[dict]:
    rows = audit._list_partition(PARTITION, limit)
    for r in rows:
        try:
            r["cases"] = json.loads(r.get("cases") or "[]")
        except ValueError:
            r["cases"] = []
    return rows


def approve(proposal_id: str) -> dict:
    """Publish one proposal's policy. The only code path that writes to the policy store."""
    rows = [r for r in list_proposals(limit=200) if r.get("pk") == proposal_id]
    if not rows:
        raise LookupError(f"no proposal {proposal_id}")
    p = rows[0]
    if p.get("valid") != "true" or not p.get("statement"):
        raise ValueError("only a proposal Cedar accepted can be approved")
    if p.get("status") == "approved":
        raise ValueError("already approved")
    name, statement = p["name"], p["statement"]
    key = f"cedar/policies/{name}.cedar"

    bucket = os.environ.get("LEASH_CEDAR_S3_BUCKET")
    if bucket:
        import boto3

        s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))
        resp = s3.put_object(Bucket=bucket, Key=key, Body=statement.encode("utf-8"), ContentType="text/plain")
        where, version = f"s3://{bucket}/{key}", str(resp.get("VersionId", ""))
    else:
        path = authz.cedar_dir() / "policies" / f"{name}.cedar"
        path.write_text(statement, encoding="utf-8", newline="\n")
        where, version = str(path), ""
    authz._LOCAL.clear()
    authz._S3.clear()  # next decision re-reads the store
    audit.write_generic(proposal_id, PARTITION, {**{k: v for k, v in p.items() if k not in ("pk", "sk", "gsi1pk", "cases")},
                                                 "cases": json.dumps(p.get("cases", [])), "status": "approved",
                                                 "published_to": where, "object_version": version})
    return {"id": proposal_id, "name": name, "published_to": where, "object_version": version,
            "policy_version": authz.policy_version()}
