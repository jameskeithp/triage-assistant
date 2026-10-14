"""Risk scoring: rank incidents by real risk, not raw severity.

score = blended severity (60%) + incident breadth (25%) + freshness (15%)

Breadth rewards correlation doing its job: N related findings on one resource
is more alarming than N isolated alerts. Freshness decays so stale incidents
sink below new ones.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from .models import Incident


def score_incident(incident: Incident, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    top = incident.top_severity

    breadth = min(10.0, 2.0 * math.log2(1 + len(incident.findings)) * 2.5)

    latest = max((f.last_seen for f in incident.findings), default=now)
    age_hours = max(0.0, (now - latest).total_seconds() / 3600.0)
    freshness = 10.0 * math.exp(-age_hours / 48.0)  # ~half-life of 33h

    score = 0.60 * top + 0.25 * breadth + 0.15 * freshness
    return round(min(10.0, score), 2)


def rank(incidents: list[Incident]) -> list[Incident]:
    for incident in incidents:
        incident.risk_score = score_incident(incident)
    return sorted(incidents, key=lambda i: i.risk_score, reverse=True)
