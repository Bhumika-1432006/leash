"""Unit tests for the Leash agent tools and handler. No AWS, no Bedrock, no cedarpy."""

import pytest

from agent import aws_helpers, handler, tools


# --- fake boto3 clients ------------------------------------------------------


class FakeEc2:
    def __init__(self, env):
        self.env = env
        self.terminated = []

    def describe_instances(self, InstanceIds):
        tags = [{"Key": "Name", "Value": "leash-box"}]
        if self.env:
            tags.append({"Key": "env", "Value": self.env})
        return {"Reservations": [{"Instances": [{"InstanceId": InstanceIds[0], "State": {"Name": "running"}, "Tags": tags}]}]}

    def terminate_instances(self, **kwargs):
        self.terminated.append(kwargs)
        return {}


class FakeSsm:
    def __init__(self):
        self.sent = []

    def send_command(self, **kwargs):
        self.sent.append(kwargs)
        return {"Command": {"CommandId": "cmd-1"}}

    def get_command_invocation(self, CommandId, InstanceId):
        return {"Status": "Success", "StandardOutputContent": "disk_used_percent before=93 after=41\n",
                "StandardErrorContent": ""}


class FakeEcs:
    def __init__(self, env):
        self.env = env
        self.updated = []

    def describe_services(self, cluster, services):
        return {"services": [{"serviceArn": f"arn:aws:ecs:us-east-1:1:service/{cluster}/{services[0]}",
                              "runningCount": 0, "desiredCount": self.desired, "status": "ACTIVE"}]}

    def list_tags_for_resource(self, resourceArn):
        return {"tags": [{"key": "env", "value": self.env}] if self.env else []}

    desired = 1

    def update_service(self, **kwargs):
        self.updated.append(kwargs)
        return {"service": {"desiredCount": kwargs.get("desiredCount", self.desired), "status": "ACTIVE"}}


class FakeAsg:
    def __init__(self, env):
        self.env = env
        self.set = []

    def describe_tags(self, Filters):
        return {"Tags": [{"Key": "env", "Value": self.env}]}

    def set_desired_capacity(self, **kwargs):
        self.set.append(kwargs)
        return {}


@pytest.fixture
def clients(monkeypatch):
    """Install fake clients into aws_helpers.client; tests set the env per resource type."""
    box = {"ec2": FakeEc2("dev"), "ssm": FakeSsm(), "ecs": FakeEcs("dev"), "autoscaling": FakeAsg("dev")}
    monkeypatch.setattr(aws_helpers, "client", lambda name: box[name])
    monkeypatch.setattr(tools.aws, "client", lambda name: box[name])
    return box


@pytest.fixture(autouse=True)
def incident():
    tools.set_context("test-incident", "leash-disk-dev")


# --- clean_disk ---------------------------------------------------------------


def test_clean_disk_denied_on_prod(clients, deny_prod, audit_rows):
    clients["ec2"] = FakeEc2("prod")
    out = clean = tools.clean_disk("i-prod")
    assert "DENIED" in out and "ForbidProd" in out
    assert clients["ssm"].sent == []  # nothing executed
    assert len(audit_rows) == 1
    row = audit_rows[0]
    assert row["action"] == "cleanDisk" and row["resource_env"] == "prod"
    assert row["decision"].allowed is False and row["decision"].policy_ids == ["ForbidProd"]
    assert row["incident_id"] == "test-incident" and row["alarm_name"] == "leash-disk-dev"
    assert clean == out


def test_clean_disk_allowed_on_dev_calls_ssm(clients, allow, audit_rows):
    out = tools.clean_disk("i-dev")
    assert out.startswith("ALLOWED by PermitDevRemediation")
    assert "before=93 after=41" in out
    sent = clients["ssm"].sent
    assert len(sent) == 1
    assert sent[0]["DocumentName"] == "AWS-RunShellScript" and sent[0]["InstanceIds"] == ["i-dev"]
    script = "\n".join(sent[0]["Parameters"]["commands"])
    assert "/tmp/leash-fill*" in script and "journalctl --vacuum-size=50M" in script and "*.gz" in script
    assert allow[0] == {"action": "cleanDisk", "resource_type": "Instance", "resource_id": "i-dev",
                        "resource_env": "dev", "context": None}
    assert audit_rows[0]["decision"].allowed is True and "Success" in audit_rows[0]["result"]


def test_untagged_instance_reports_unknown_env(clients, deny_prod):
    clients["ec2"] = FakeEc2(None)
    tools.clean_disk("i-none")
    assert deny_prod[0]["resource_env"] == "unknown"


# --- terminate_instance --------------------------------------------------------


def test_terminate_never_calls_ec2_even_when_allowed(clients, allow, audit_rows):
    out = tools.terminate_instance("i-dev")
    assert "refused by hard-coded guard" in out
    assert clients["ec2"].terminated == []
    assert audit_rows[0]["action"] == "terminateInstance"
    assert audit_rows[0]["result"] == "refused by hard-coded guard"


def test_terminate_denied_is_audited(clients, monkeypatch, decision_cls, audit_rows):
    monkeypatch.setattr("common.authz.authorize",
                        lambda *a, **k: decision_cls(False, ["ForbidDestructive"], "forbid", []))
    out = tools.terminate_instance("i-dev")
    assert "DENIED by ForbidDestructive" in out
    assert clients["ec2"].terminated == []
    assert audit_rows[0]["decision"].policy_ids == ["ForbidDestructive"]


# --- restart_service / scale_group ---------------------------------------------


def test_restart_service_allowed(clients, allow, audit_rows):
    out = tools.restart_service("leash-dev", "leash-api-dev")
    assert out.startswith("ALLOWED")
    assert clients["ecs"].updated[0] == {"cluster": "leash-dev", "service": "leash-api-dev", "forceNewDeployment": True}
    assert allow[0]["resource_type"] == "EcsService" and allow[0]["resource_id"] == "leash-dev/leash-api-dev"


def test_restart_service_restores_desired_count_when_zero(clients, allow):
    clients["ecs"].desired = 0
    out = tools.restart_service("leash-dev", "leash-api-dev")
    assert out.startswith("ALLOWED") and "desired count was 0, set to 1" in out
    assert clients["ecs"].updated[0] == {"cluster": "leash-dev", "service": "leash-api-dev",
                                         "forceNewDeployment": True, "desiredCount": 1}


def test_scale_group_passes_context_and_denial_skips_call(clients, monkeypatch, decision_cls, audit_rows):
    seen = {}

    def fake_authorize(action, resource_type, resource_id, resource_env, context=None):
        seen.update(action=action, context=context)
        return decision_cls(False, ["ForbidScaleAboveCap"], "forbid", [])

    monkeypatch.setattr("common.authz.authorize", fake_authorize)
    out = tools.scale_group("leash-dev-asg", 6)
    assert seen == {"action": "scaleGroup", "context": {"desiredCapacity": 6}}
    assert "DENIED by ForbidScaleAboveCap" in out
    assert clients["autoscaling"].set == []


def test_scale_group_allowed_sets_capacity(clients, allow):
    tools.scale_group("leash-dev-asg", 2)
    assert clients["autoscaling"].set[0]["DesiredCapacity"] == 2


# --- handler --------------------------------------------------------------------


ALARM_EVENT = {
    "source": "aws.cloudwatch",
    "detail-type": "CloudWatch Alarm State Change",
    "detail": {
        "alarmName": "leash-disk-dev",
        "state": {"value": "ALARM"},
        "configuration": {
            "metrics": [{"id": "m1", "metricStat": {"metric": {
                "namespace": "CWAgent", "name": "disk_used_percent",
                "dimensions": {"InstanceId": "i-0abc", "path": "/", "fstype": "xfs", "device": "nvme0n1p1"}}}}]
        },
    },
}


def test_handler_parses_alarm_dimensions():
    parsed = handler.parse_event(ALARM_EVENT)
    assert parsed["mode"] == "alarm"
    assert parsed["alarm_name"] == "leash-disk-dev" and parsed["state"] == "ALARM"
    assert parsed["dimensions"]["InstanceId"] == "i-0abc" and parsed["dimensions"]["path"] == "/"
    assert "i-0abc" in handler.build_alarm_prompt(parsed)


def test_handler_parses_chat():
    parsed = handler.parse_event({"mode": "chat", "message": "  terminate i-1 "})
    assert parsed == {"mode": "chat", "alarm_name": "", "state": "", "dimensions": {}, "message": "terminate i-1"}


def test_handler_runs_agent_and_notifies_for_alarm(monkeypatch):
    prompts, published = [], []

    class FakeAgent:
        messages = []
        system_prompt = ""

        def __call__(self, prompt):
            prompts.append(prompt)
            return "fixed the disk"

    monkeypatch.setattr(handler, "_AGENT", None)
    monkeypatch.setattr(handler, "build_agent", lambda incident_id: FakeAgent())
    monkeypatch.setattr(tools, "notify", lambda summary: published.append(summary) or "ok")
    out = handler.handler(ALARM_EVENT, None)
    assert out["reply"] == "fixed the disk" and out["incident_id"].startswith("leash-disk-dev-")
    assert "i-0abc" in prompts[0]
    assert published and "fixed the disk" in published[0]
    assert tools._CTX == {"incident_id": out["incident_id"], "alarm_name": "leash-disk-dev"}


def test_handler_ignores_ok_state(monkeypatch):
    monkeypatch.setattr(handler, "build_agent", lambda incident_id: pytest.fail("agent must not run"))
    event = {**ALARM_EVENT, "detail": {**ALARM_EVENT["detail"], "state": {"value": "OK"}}}
    assert handler.handler(event, None)["reply"].startswith("ignored")


# --- audit failure is visible in the tool's return string ----------------------


def test_audit_write_failure_is_reported_in_result(clients, allow, monkeypatch):
    def broken_write_audit(**kwargs):
        raise RuntimeError("dynamodb down")

    monkeypatch.setattr("common.audit.write_audit", broken_write_audit)
    out = tools.restart_service("leash-dev", "leash-api-dev")
    assert out.startswith("ALLOWED")
    assert out.endswith(tools.AUDIT_FAILED)
    assert clients["ecs"].updated  # the action itself still ran
