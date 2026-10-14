"""Normalize GuardDuty and Security Hub finding JSON into Finding objects."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import Finding

# NOTE: account IDs below are the AWS documentation example (123456789012),
# not any real account.


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _guardduty_severity(raw_sev: float) -> float:
    # GuardDuty: 0-10 already (Low 0.1-3.9, Medium 4-6.9, High 7-8.9, Critical 9-10).
    return max(0.0, min(10.0, float(raw_sev)))


def _securityhub_severity(label: str, normalized: float | None) -> float:
    if normalized is not None:
        # Security Hub's Normalized field is 0-100; ours is 0-10.
        value = float(normalized)
        if value > 10.0:
            value = value / 10.0
        return max(0.0, min(10.0, value))
    return {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.5,
            "INFORMATIONAL": 1.0}.get(str(label).upper(), 5.0)


def _from_guardduty(item: dict) -> Finding:
    service = item.get("Service", {})
    resource = item.get("Resource", {})
    inst = resource.get("InstanceDetails", {}) or {}
    resource_id = inst.get("InstanceId") or resource.get("ResourceType", "unknown")
    action = service.get("Action", {}) or {}
    return Finding(
        id=item.get("Id", "gd-unknown"),
        source="guardduty",
        title=item.get("Title", item.get("Type", "GuardDuty finding")),
        description=item.get("Description", ""),
        severity=_guardduty_severity(service.get("Severity", item.get("Severity", 5.0))),
        resource_id=resource_id,
        account_id=item.get("AccountId", "123456789012"),
        region=item.get("Region", "us-east-1"),
        finding_type=item.get("Type", "unknown"),
        first_seen=_parse_time(item.get("CreatedAt")),
        last_seen=_parse_time(item.get("UpdatedAt")),
        raw=item,
    )


def _from_securityhub(item: dict) -> Finding:
    resources = item.get("Resources", []) or [{}]
    raw_id = resources[0].get("Id", "unknown")
    # ARNs carry the name after the last "/" (or ":" when there is no "/").
    resource_id = raw_id.split("/")[-1].rsplit(":", 1)[-1] if "/" in raw_id else raw_id.rsplit(":", 1)[-1]
    sev = item.get("Severity", {}) or {}
    return Finding(
        id=item.get("Id", "sh-unknown"),
        source="securityhub",
        title=item.get("Title", "Security Hub finding"),
        description=item.get("Description", ""),
        severity=_securityhub_severity(sev.get("Label"), sev.get("Normalized")),
        resource_id=resource_id,
        account_id=item.get("AwsAccountId", "123456789012"),
        region=item.get("Region", "us-east-1"),
        finding_type=item.get("Types", ["unknown"])[0]
        if item.get("Types") else "unknown",
        first_seen=_parse_time(item.get("FirstObservedAt")),
        last_seen=_parse_time(item.get("LastObservedAt")),
        raw=item,
    )


def load_findings(path: str) -> list[Finding]:
    """Load a JSON file shaped like {"guardduty": [...], "securityhub": [...]}."""
    with open(path) as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for item in data.get("guardduty", []):
        findings.append(_from_guardduty(item))
    for item in data.get("securityhub", []):
        findings.append(_from_securityhub(item))
    return findings
