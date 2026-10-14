"""End-to-end pipeline: ingest -> correlate -> rank -> summarize -> runbook.

Usage:
    python3 -m triage.pipeline data/sample_findings.json [--provider stub|openai]
"""

from __future__ import annotations

import argparse

from .correlate import correlate
from .ingest import load_findings
from .providers import get_provider
from .runbook import draft_runbook, summarize
from .score import rank


def run(path: str, provider_name: str = "stub"):
    provider = get_provider(provider_name)
    findings = load_findings(path)
    incidents = rank(correlate(findings))
    for incident in incidents:
        summarize(incident, provider)
        draft_runbook(incident, provider)
    return incidents


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage Assistant pipeline")
    parser.add_argument("findings", help="JSON file with guardduty/securityhub findings")
    parser.add_argument("--provider", default="stub", help="stub or openai")
    args = parser.parse_args()

    incidents = run(args.findings, args.provider)
    print(f"Processed {len(incidents)} incident(s)\n")
    for i, inc in enumerate(incidents, 1):
        print(f"=== Incident {i}: {inc.key} (risk {inc.risk_score}/10) ===")
        print(f"Findings: {', '.join(inc.finding_ids)}")
        print(f"Summary: {inc.summary}\n")
        print(f"{inc.runbook}\n")


if __name__ == "__main__":
    main()
