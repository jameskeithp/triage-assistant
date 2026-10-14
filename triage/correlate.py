"""Group related findings into incidents.

Correlation key: (account, resource) within a rolling time window, with a
bonus signal when finding types share a technique family (e.g. credential
exfiltration + unusual API calls against the same instance).
"""

from __future__ import annotations

from datetime import timedelta

from .models import Finding, Incident

WINDOW = timedelta(hours=6)


def _technique_family(finding_type: str) -> str:
    t = finding_type.lower()
    if "credential" in t or "exfiltrat" in t:
        return "credential-access"
    if "unauthorizedaccess" in t or "tor" in t or "bruteforce" in t:
        return "initial-access"
    if "policy" in t or "iam" in t or "privilege" in t:
        return "privilege-escalation"
    if "s3" in t or "bucket" in t or "public" in t:
        return "data-exposure"
    if "malware" in t or "backdoor" in t or "c2" in t:
        return "malware-c2"
    return "other"


def correlate(findings: list[Finding]) -> list[Incident]:
    ordered = sorted(findings, key=lambda f: f.first_seen)
    incidents: list[Incident] = []

    for finding in ordered:
        placed = False
        for incident in incidents:
            anchor = incident.findings[0]
            same_target = (
                anchor.account_id == finding.account_id
                and anchor.resource_id == finding.resource_id
            )
            in_window = abs((finding.first_seen - anchor.last_seen)) <= WINDOW
            if same_target and in_window:
                incident.findings.append(finding)
                if finding.last_seen > anchor.last_seen:
                    anchor.last_seen = finding.last_seen
                placed = True
                break
        if not placed:
            fam = _technique_family(finding.finding_type)
            incidents.append(
                Incident(
                    key=f"{finding.account_id}:{finding.resource_id}:{fam}",
                    findings=[finding],
                )
            )
    return incidents
