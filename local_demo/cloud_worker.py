#!/usr/bin/env python
"""The brain, running anywhere: the Leash agent on this machine, wired to the AWS stack by SQS.

    PYTHONPATH=src python local_demo/cloud_worker.py            # uses stack "leash" in us-east-1
    PYTHONPATH=src python local_demo/cloud_worker.py --once     # drain what is queued, then exit

What is real here: every AWS resource (EC2, SSM, ECS, Auto Scaling, DynamoDB, SNS), the alarms
that trigger the run, and every authorisation decision, which is made by the Leash authorizer
Lambda in AWS from the Cedar policies in S3. It also writes the audit row before answering.
What runs locally: only the language model (Ollama), because Amazon Bedrock is not part of the
AWS Free plan. Set LEASH_LOCAL_MODEL=0 with Bedrock access and this same file uses Bedrock.

Two queues, both created by the stack:
  IncidentQueue   EventBridge delivers "CloudWatch Alarm State Change" events here
  RequestQueue    the API Lambda drops /ask and /redteam requests here
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

STACK = os.environ.get("STACK_NAME", "leash")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def stack_outputs() -> dict:
    cf = boto3.client("cloudformation", region_name=REGION)
    outs = cf.describe_stacks(StackName=STACK)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outs}


def configure(outputs: dict) -> None:
    """Environment the agent code reads; real AWS everywhere, the authorizer Lambda for Cedar."""
    os.environ.setdefault("LEASH_LOCAL_MODEL", "1")
    os.environ.setdefault("OLLAMA_MODEL_ID", "qwen3:8b")
    os.environ["AWS_REGION"] = REGION
    os.environ["LEASH_AUTHZ_FUNCTION"] = outputs["AuthzFunctionName"]
    os.environ["AUDIT_TABLE"] = outputs["AuditTableName"]
    os.environ["ALERT_TOPIC_ARN"] = outputs.get("AlertTopicArn", "")
    os.environ["DEV_INSTANCE_ID"] = outputs.get("DevInstanceId", "")
    os.environ["PROD_INSTANCE_ID"] = outputs.get("ProdInstanceId", "")
    os.environ["ASG_NAME"] = outputs.get("AsgName", "leash-dev-asg")
    os.environ.setdefault("ENV_TAG_KEY", "env")
    os.environ.setdefault("SCALE_CAP", "4")
    os.environ.pop("LEASH_LOCAL_AUTHZ", None)  # Cedar is evaluated in AWS, not here
    os.environ.pop("LEASH_SANDBOX_UNLEASHED", None)


def handle_incident(body: dict) -> None:
    from agent.handler import handler

    event = body  # the EventBridge event itself, delivered as the SQS message body
    print(f"[incident] alarm={((event.get('detail') or {}).get('alarmName'))}", flush=True)
    result = handler(event, None)
    print(f"[incident] {result['incident_id']}: {str(result['reply'])[:300]}", flush=True)


def handle_request(body: dict) -> None:
    kind = body.get("kind")
    if kind == "chat":
        from agent.handler import handler
        from common import audit

        incident_id = body["incident_id"]
        print(f"[chat] {incident_id}: {body['message'][:120]}", flush=True)
        result = handler({"mode": "chat", "message": body["message"], "incident_id": incident_id}, None)
        audit.write_reply(incident_id, str(result["reply"]))
        print(f"[chat] reply written: {str(result['reply'])[:200]}", flush=True)
    elif kind == "redteam":
        from redteam import attacks as attacks_mod, runner
        from redteam.handler import resource_ids

        n = int(body.get("n", 20))
        arms = tuple(body.get("arms") or ("leashed", "unleashed"))
        run_id = body.get("run_id") or runner._now_id()
        print(f"[redteam] run {run_id}: {n} attacks, arms={arms}", flush=True)
        catalogue = attacks_mod.build_catalogue(resource_ids(), n, use_model=bool(body.get("use_model", True)))

        def on_row(row):
            print(f"[redteam] {row['index']:3d} {row['tactic']:13s} persuaded={row.get('persuaded')} "
                  f"leashed_exec={row.get('leashed_executed')} unleashed_exec={row.get('unleashed_executed')} "
                  f"denials={row.get('leashed_denials')}", flush=True)

        runner.run_batch(catalogue, run_id=run_id, arms=arms, on_row=on_row)
        print(f"[redteam] run {run_id} done", flush=True)
    else:
        print(f"[request] unknown kind {kind!r}: {json.dumps(body)[:200]}", flush=True)


def main(argv: list[str]) -> int:
    once = "--once" in argv
    outputs = stack_outputs()
    configure(outputs)
    sqs = boto3.client("sqs", region_name=REGION)
    queues = [("incident", outputs["IncidentQueueUrl"], handle_incident),
              ("request", outputs["RequestQueueUrl"], handle_request)]
    print(f"Leash worker: brain on this machine ({os.environ['OLLAMA_MODEL_ID']}), leash in AWS "
          f"({outputs['AuthzFunctionName']}). Polling {len(queues)} queues. Ctrl+C to stop.", flush=True)
    idle_rounds = 0
    last_beat = 0.0
    while True:
        got = False
        if time.time() - last_beat > 20:
            try:
                from common import audit

                audit.write_heartbeat(os.environ["OLLAMA_MODEL_ID"], os.environ.get("COMPUTERNAME") or os.uname().nodename)
                last_beat = time.time()
            except Exception as exc:  # noqa: BLE001
                print(f"[heartbeat] failed: {exc}", flush=True)
        for name, url, fn in queues:
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
                                       VisibilityTimeout=900)
            for msg in resp.get("Messages", []):
                got = True
                try:
                    body = json.loads(msg["Body"])
                    fn(body)
                except Exception as exc:  # noqa: BLE001 - keep the worker alive; SQS will retry
                    print(f"[{name}] failed: {type(exc).__name__}: {exc}", flush=True)
                else:
                    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if once and not got:
            idle_rounds += 1
            if idle_rounds >= 2:
                return 0
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nstopped")
