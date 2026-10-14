"""Dependency-free verification: run the full pipeline with the stub provider.

Run: python3 -m tests.test_pipeline   (from the triage-assistant directory)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.pipeline import run


def main() -> None:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    incidents = run(os.path.join(base, "data", "sample_findings.json"), "stub")

    # 1. All 5 sample findings are processed.
    total = sum(len(i.findings) for i in incidents)
    assert total == 5, f"expected 5 findings, got {total}"

    # 2. The two i-0abc123 GuardDuty findings correlate into ONE incident.
    exfil = [i for i in incidents if "i-0abc123" in i.key]
    assert len(exfil) == 1, f"expected 1 incident for i-0abc123, got {len(exfil)}"
    assert len(exfil[0].findings) == 2, "expected 2 findings in the i-0abc123 incident"

    # 3. Incidents are ranked by risk, descending.
    scores = [i.risk_score for i in incidents]
    assert scores == sorted(scores, reverse=True), f"not ranked: {scores}"
    assert all(0.0 <= s <= 10.0 for s in scores), f"score out of range: {scores}"

    # 4. Risk != raw severity (the documented design): the fresh 8.2 incident
    #    on i-0abc123 (2 correlated findings, ~4h old) outranks the stale 9.1
    #    root-credential finding (~36h old, single finding). Both stay top-two.
    top_two_types = {f.finding_type for i in incidents[:2] for f in i.findings}
    assert "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" in top_two_types
    assert "Policy:IAMUser/RootCredentialUsage" in top_two_types
    assert "i-0abc123" in incidents[0].key, (
        "fresh correlated incident should outrank the stale single finding"
    )

    # 5. Every incident has a summary and a human-approval-labeled runbook.
    for inc in incidents:
        assert inc.summary, f"missing summary for {inc.key}"
        assert inc.runbook, f"missing runbook for {inc.key}"
        assert "human approval" in inc.runbook.lower(), (
            f"runbook for {inc.key} missing human-approval label"
        )

    print(f"OK: {len(incidents)} incidents from 5 findings, ranked, with summaries "
          f"and human-approved runbooks (stub provider).")


if __name__ == "__main__":
    main()
