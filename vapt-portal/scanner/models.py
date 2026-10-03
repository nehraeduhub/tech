"""Shared data structures for findings and scan results."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

# Severity ordering used for sorting and scoring.
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# CVSS-ish base weight per severity, used for the headline risk score.
SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}


@dataclass
class Finding:
    """A single assessment observation."""

    title: str
    severity: str  # critical | high | medium | low | info
    category: str  # OWASP-style category label
    description: str
    evidence: str = ""
    recommendation: str = ""
    # Attack classes this weakness could enable (risk context, not a how-to).
    attack_surface: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    check: str = ""  # which check produced this

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    normalized_url: str
    started_at: str = ""
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    tool_log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def log(self, msg: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.tool_log.append(f"[{stamp}] {msg}")

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def risk_score(self) -> float:
        """Weighted 0-100 score. Higher = worse."""
        counts = self.severity_counts()
        raw = sum(SEVERITY_WEIGHT[s] * n for s, n in counts.items())
        # Normalise with diminishing returns so a handful of criticals ~ 90s.
        score = 100 * (1 - (0.85 ** raw))
        return round(min(score, 100.0), 1)

    def risk_rating(self) -> str:
        score = self.risk_score()
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        if score >= 10:
            return "Low"
        return "Informational"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "normalized_url": self.normalized_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk_score": self.risk_score(),
            "risk_rating": self.risk_rating(),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "meta": self.meta,
            "tool_log": self.tool_log,
            "errors": self.errors,
        }
