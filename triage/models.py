"""Shared data models: normalized findings and correlated incidents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Finding:
    """One normalized security finding, regardless of source."""

    id: str
    source: str            # "guardduty" | "securityhub"
    title: str
    description: str
    severity: float        # normalized 0.0 – 10.0
    resource_id: str       # e.g. instance id, bucket name, IAM user ARN fragment
    account_id: str
    region: str
    finding_type: str      # e.g. "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
    first_seen: datetime
    last_seen: datetime
    raw: dict = field(default_factory=dict)


@dataclass
class Incident:
    """A correlated group of related findings — one thing for a human to triage."""

    key: str
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
    runbook: str = ""

    @property
    def finding_ids(self) -> list[str]:
        return [f.id for f in self.findings]

    @property
    def top_severity(self) -> float:
        return max((f.severity for f in self.findings), default=0.0)
