# Submission checklist — First Commit (WeMakeDevs x AWS), rules mapped to evidence

Source: https://www.wemakedevs.org/aws/first-commit/rules and the hackathon page. Tick each row
before the form is submitted on Sunday 20 Sept 2026; the deadline time is published on the
schedule page and the form closes hard.

## The three deliverables

| Rule | Where it is | Done |
| --- | --- | --- |
| Public repository | https://github.com/Chirag6722/leash (public, MIT) | ☐ still public on submission day |
| Demo video, YouTube, **under three minutes**, public or unlisted | link goes in the form; shot list in [DEMO-SCRIPT.md](DEMO-SCRIPT.md) | ☐ uploaded ☐ opens in a signed-out / private window ☐ < 3:00 |
| Short writeup: problem, build, where AWS fits | [WRITEUP.md](WRITEUP.md) (paste into the form) | ☐ pasted |
| One submission per team | one form, submitted once | ☐ |

## Rules that can disqualify

| Rule | How Leash satisfies it |
| --- | --- |
| New work, started after the event opened | first commit 18 Sept 2026; every commit is inside 17–20 Sept |
| Repository history must match the event dates | no history rewriting, no squashed imports of older work |
| "Your project has to use AWS, and your demo video has to show it" | **record the video against the deployed stack**: CloudWatch alarm going red, the Verified Permissions denial, the DynamoDB-backed dashboard. The local demo is a fallback, not the video |
| AI coding tools must be listed in the writeup | "AI tools used" section in WRITEUP.md and README.md |
| Non-original work credited and licensed | Strands Agents (Apache-2.0), cedarpy (Apache-2.0), nginx public ECR image; all named in the README |

## Judging criteria and where each one is answered

| Criterion (from the hackathon page) | Evidence |
| --- | --- |
| Idea and impact: solves a real problem, what changes for people | WRITEUP "Impact, measured" table; red team: 18/20 destructive without the leash, 0/20 with it; dashboard **Alarm → fixed** tile |
| Built on AWS (mandatory) | 12 services in the README table; Strands + Cedar are AWS open-source projects |
| Learning: "tell us what you learned, and it counts" | WRITEUP "What we learned" (six concrete lessons) |
| Execution: does it work | 121 passing tests with real Cedar evaluation; CI on every push; live URL in the form; all five demo beats and a 20-attack red-team run verified on the deployed stack |
| Demo video: what it does, who it is for, where AWS fits | DEMO-SCRIPT.md beats 1–5, AWS console shots included on purpose |

## Ship It track specifics

- Live URL: http://leash-dashboard-431578779465-us-east-1.s3-website-us-east-1.amazonaws.com
  (API https://zjebhhtr9h.execute-api.us-east-1.amazonaws.com). Keep the stack up through
  judging; the prod decoy is stopped. The brain must be running (`local_demo/cloud_worker.py`)
  for the Ask box and alarms to be answered; the audit trail and policies are served regardless.
- Cost guard: the HTTP API is throttled (5 req/s, burst 10); the agent role has explicit denies on
  every delete API; tear down with `scripts/teardown.sh` once results are announced.

## Extra credit

- Blog on AWS Builder Center (top five blog writers win keyboards): draft in [BLOG.md](BLOG.md).
- Repository description and topics are set on GitHub (aws, cedar, strands-agents, verified-permissions).
