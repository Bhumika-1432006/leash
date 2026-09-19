"""English -> Cedar: propose, prove, publish only on approve (#21)."""

import json
from pathlib import Path

import pytest

from common import authz, proposals

ROOT = Path(__file__).resolve().parents[2]


def scale_allowed(n: int) -> bool:
    return authz.authorize("scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": n}).allowed


# --- template drafter -------------------------------------------------------------------------


@pytest.mark.parametrize("text,name,fragment", [
    ("the bot may never scale above 2", "ForbidScaleAboveCap", "context.desiredCapacity > 2"),
    ("never touch prod", "ForbidProd", 'resource.env == "prod"'),
    ("the bot must not restart anything on staging", "ForbidRestartServiceOnStaging", '"restartService"'),
    ("allow cleanup on staging", "PermitCleanDiskOnStaging", "permit ("),
    ("never delete anything", "ForbidDeleteResource", '"deleteResource"'),
    ("don't terminate on dev", "ForbidTerminateInstanceOnDev", '"terminateInstance"'),
])
def test_template_drafts_the_sentences_operators_use(text, name, fragment):
    d = proposals.template_draft(text)
    assert d is not None and d.name == name and fragment in d.statement


def test_template_returns_none_when_nothing_fits():
    assert proposals.template_draft("make it faster") is None


def test_every_template_draft_passes_cedar_validation(store):
    files, _ = authz._policy_files()
    schema = json.loads(files["schema"])
    for text in ["never scale above 3", "never touch staging", "may not clean up prod",
                 "allow restart on dev", "never kill anything"]:
        d = proposals.template_draft(text)
        assert d is not None, text
        v = proposals.validate(d.statement, schema)
        assert v.ok, (text, v.errors)


# --- validation and proof ---------------------------------------------------------------------


def test_validate_rejects_unknown_attribute_and_garbage(store):
    schema = json.loads(authz._policy_files()[0]["schema"])
    assert not proposals.validate('forbid (principal, action, resource) when { resource.nope == 1 };', schema).ok
    assert not proposals.validate("this is not cedar", schema).ok
    assert proposals.validate('forbid (principal, action, resource) when { resource.env == "prod" };', schema).ok


def test_prove_reports_exactly_what_would_change(store):
    files, _ = authz._policy_files()
    d = proposals.template_draft("never scale above 2")
    proof = proposals.prove(d.name, d.statement, files)
    assert proof["replaces"] is True
    assert proof["changed"] == ["scale dev to 4: ALLOW -> DENY"]
    d2 = proposals.template_draft("allow cleanup on staging")
    assert proposals.prove(d2.name, d2.statement, files)["changed"] == ["clean a staging disk: DENY -> ALLOW"]
    d3 = proposals.template_draft("never touch prod")  # already the law
    assert proposals.prove(d3.name, d3.statement, files)["changed"] == []


# --- propose never publishes; approve is the only write ----------------------------------------


def test_propose_stores_a_row_and_changes_nothing(store):
    assert scale_allowed(4)
    row = proposals.propose("the bot may never scale above 2")
    assert row["valid"] == "true" and row["status"] == "proposed" and row["source"] == "template"
    assert row["changed"] == ["scale dev to 4: ALLOW -> DENY"]
    assert scale_allowed(4), "proposing must not publish"
    assert (store / "policies" / "ForbidScaleAboveCap.cedar").read_text() == \
        (ROOT / "cedar" / "policies" / "ForbidScaleAboveCap.cedar").read_text()
    assert proposals.list_proposals()[0]["pk"] == row["pk"]


def test_approve_publishes_and_the_next_decision_changes(store):
    row = proposals.propose("the bot may never scale above 2")
    assert scale_allowed(4)
    out = proposals.approve(row["pk"])
    assert out["name"] == "ForbidScaleAboveCap" and out["published_to"].endswith("ForbidScaleAboveCap.cedar")
    assert not scale_allowed(4)
    assert scale_allowed(2)
    d = authz.authorize("scaleGroup", "AutoScalingGroup", "leash-dev-asg", "dev", {"desiredCapacity": 4})
    assert d.policy_ids == ["ForbidScaleAboveCap"]
    assert proposals.list_proposals()[0]["status"] == "approved"
    with pytest.raises(ValueError, match="already approved"):
        proposals.approve(row["pk"])


def test_a_new_policy_name_is_loaded_and_enforced(store):
    assert not authz.authorize("cleanDisk", "Instance", "i-s", "staging").allowed
    row = proposals.propose("allow cleanup on staging")
    proposals.approve(row["pk"])
    assert authz.authorize("cleanDisk", "Instance", "i-s", "staging").allowed
    ids = [p["id"] for p in authz.list_policies()]
    assert ids[:4] == list(authz.POLICY_NAMES) and "PermitCleanDiskOnStaging" in ids
    # a forbid still wins: prod stays closed even with a new permit around
    assert not authz.authorize("cleanDisk", "Instance", "i-p", "prod").allowed


def test_invalid_or_unknown_cannot_be_approved(store):
    row = proposals.propose("make it faster")
    assert row["valid"] == "false" and row["statement"] == ""
    with pytest.raises(ValueError):
        proposals.approve(row["pk"])
    with pytest.raises(LookupError):
        proposals.approve("proposal-nope")


def test_model_draft_is_used_only_if_cedar_accepts_it(store):
    good = 'forbid (principal, action == Leash::Action::"restartService", resource) when { resource.env == "dev" };'
    row = proposals.propose("never restart on dev", drafter=lambda prompt: "```cedar\n" + good + "\n```")
    assert row["source"] == "model" and row["valid"] == "true" and row["statement"].strip() == good
    row = proposals.propose("never restart on dev", drafter=lambda prompt: "sure! forbid everything lol")
    assert row["source"] == "model (rejected) -> template" and row["valid"] == "true"
    assert '"restartService"' in row["statement"]
    row = proposals.propose("never restart on dev", drafter=lambda prompt: (_ for _ in ()).throw(RuntimeError("no model")))
    assert row["source"] == "model (failed) -> template" and row["valid"] == "true"


def test_repo_cedar_files_are_never_written(store):
    before = {p.name: p.read_text() for p in (ROOT / "cedar" / "policies").glob("*.cedar")}
    proposals.approve(proposals.propose("never scale above 1")["pk"])
    proposals.approve(proposals.propose("allow cleanup on staging")["pk"])
    after = {p.name: p.read_text() for p in (ROOT / "cedar" / "policies").glob("*.cedar")}
    assert before == after


# --- the API routes ---------------------------------------------------------------------------


def _call(route, body=None, q=None):
    from api.handler import handler

    ev = {"routeKey": route, "queryStringParameters": q, "body": json.dumps(body) if body else None,
          "isBase64Encoded": False}
    r = handler(ev, None)
    return r["statusCode"], json.loads(r["body"])


def test_api_propose_list_approve(store):
    st, p = _call("POST /policies/propose", {"text": "the bot may never scale above 2"})
    assert st == 200 and p["valid"] == "true" and p["cases"]
    assert scale_allowed(4)
    st, lst = _call("GET /policies/proposals")
    assert st == 200 and lst["items"][0]["pk"] == p["pk"]
    st, a = _call("POST /policies/approve", {"id": p["pk"]})
    assert st == 200 and a["name"] == "ForbidScaleAboveCap"
    assert not scale_allowed(4)
    assert _call("POST /policies/approve", {"id": p["pk"]})[0] == 409
    assert _call("POST /policies/approve", {"id": "proposal-nope"})[0] == 404
    assert _call("POST /policies/approve", {"id": "nonsense"})[0] == 400
    assert _call("POST /policies/propose", {"text": ""})[0] == 400
    assert _call("POST /policies/propose", {"text": "x" * 600})[0] == 400
    st, pols = _call("GET /policies")
    assert "desiredCapacity > 2" in next(x["statement"] for x in pols["items"] if x["id"] == "ForbidScaleAboveCap")


def test_api_propose_is_queued_in_worker_mode(store, monkeypatch):
    sent = []
    monkeypatch.setenv("REQUEST_QUEUE_URL", "https://sqs.local/q")
    import api.handler as api

    class FakeSqs:
        def send_message(self, QueueUrl, MessageBody):
            sent.append(json.loads(MessageBody))

    monkeypatch.setattr(api, "_sqs_client", lambda: FakeSqs())
    st, body = _call("POST /policies/propose", {"text": "never touch staging"})
    assert st == 202 and body["status"] == "queued"
    assert sent == [{"kind": "propose", "text": "never touch staging"}]
    assert proposals.list_proposals() == []  # nothing stored until the worker drafts it
