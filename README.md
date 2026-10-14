# Triage Assistant — agentic cloud-security finding triage

Hackathon project for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026),
indie track. Application submitted 2026-10-13; acceptance notification by Oct 26, 9 AM ET.

## What it does

Ingests AWS GuardDuty + Security Hub findings, correlates related alerts into single
incidents, ranks them by real risk (not raw severity), and drafts remediation runbooks
for human approval.

## Architecture

```
GuardDuty / SecurityHub JSON
        │  ingest.py      → normalized Finding objects
        ▼
   correlate.py           → incidents (grouped by resource + time + technique)
        ▼
    score.py              → risk-ranked incidents
        ▼
   runbook.py ──LLMProvider──▶ remediation runbook drafts (human-approved)
```

## The LLM layer is pluggable — by design

All model calls go through `triage/providers.py`'s `LLMProvider.complete()` interface.
Three providers ship:

| Provider | File | Use |
|---|---|---|
| `StubProvider` | `triage/providers.py` | Deterministic, no network. Everything is fully testable today. |
| `OpenAIProvider` | `triage/providers.py` | Live. Needs `OPENAI_API_KEY` (Friday's step). |
| Meta Model API | — | **Swap-in only.** The Meta Model API is OpenAI-compatible, so this becomes an `OpenAIProvider(base_url=..., api_key=<meta key>)` one-liner when the $150 credits land on Oct 26. No prompt or logic changes needed. |

So: build and test everything now against the stub, drop in the OpenAI key Friday
for live runs, and point at Meta's API during the sprint. One interface, three backends.

## Quick start

```bash
cd triage-assistant
python3 -m tests.test_pipeline        # runs the full pipeline on sample data with the stub
```

Live run (after Friday's key):

```bash
cp .env.example .env                   # put OPENAI_API_KEY in .env — never commit it
python3 -m triage.pipeline data/sample_findings.json --provider openai
```

## What's real vs. what's next

Real today: ingestion of GuardDuty/SecurityHub finding JSON, correlation, risk scoring,
runbook drafting behind the provider interface, sample data, and a passing test suite.

Next (Friday, with the key): live OpenAI runs, then swap the provider to Meta's API
when credits land. After that: live GuardDuty/SecurityHub pulls via boto3 (the
control-plane project's detection stack is the natural source), and the agentic loop
(draft → human approve → execute remediation via the control plane's Lambda).

## Status log

- 2026-10-13: skeleton built (stub provider, pipeline, tests). API key step deferred to Fri Oct 16.
