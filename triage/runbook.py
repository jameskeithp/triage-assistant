"""LLM-backed incident summarization and remediation-runbook drafting.

Every runbook is a DRAFT and is labeled as requiring human approval —
the agent proposes, the human disposes.
"""

from __future__ import annotations

from .models import Incident
from .providers import LLMProvider

_SUMMARY_SYSTEM = (
    "You are a cloud-security analyst triaging AWS findings. "
    "Summarize the incident in 2-3 sentences: what happened, on which resource, "
    "and why it matters. Be specific, no filler."
)

_RUNBOOK_SYSTEM = (
    "You are a cloud-security incident responder. Draft a remediation runbook "
    "for the incident described. Use numbered steps: isolate, investigate, "
    "contain, remediate, verify. Keep each step to one line with the concrete "
    "AWS action (console step, CLI command, or Config rule). End with the line: "
    "'HUMAN APPROVAL REQUIRED before executing any step.'"
)


def _incident_context(incident: Incident) -> str:
    lines = [
        f"Incident key: {incident.key}",
        f"Risk score: {incident.risk_score}/10 | Findings: {len(incident.findings)}",
    ]
    for f in incident.findings:
        lines.append(
            f"- [{f.source}] {f.title} (severity {f.severity:.1f}) "
            f"on {f.resource_id} in {f.region}; type={f.finding_type}"
        )
    return "\n".join(lines)


def summarize(incident: Incident, provider: LLMProvider) -> str:
    incident.summary = provider.complete(_SUMMARY_SYSTEM, _incident_context(incident))
    return incident.summary


def draft_runbook(incident: Incident, provider: LLMProvider) -> str:
    context = _incident_context(incident)
    if incident.summary:
        context += f"\nAnalyst summary: {incident.summary}"
    incident.runbook = provider.complete(_RUNBOOK_SYSTEM, context)
    return incident.runbook
