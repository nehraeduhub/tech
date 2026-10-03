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

# Representative CVSS 3.1 base score per severity, used when a check does not
# supply an explicit score. These are indicative, not authoritative.
SEVERITY_CVSS = {
    "critical": 9.3,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


@dataclass
class Finding:
    """A single assessment observation, modelled on a professional VAPT report."""

    title: str
    severity: str  # critical | high | medium | low | info
    category: str  # OWASP-style category label
    description: str
    evidence: str = ""
    recommendation: str = ""
    impact: str = ""
    # Attack classes this weakness could enable (risk context, not a how-to).
    attack_surface: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe: str = ""              # e.g. "CWE-693: Protection Mechanism Failure"
    cvss_score: float | None = None
    cvss_vector: str = ""
    affected: str = ""         # affected URL / host / parameter
    confidence: str = "Medium"  # High | Medium | Low
    check: str = ""            # which check produced this

    def __post_init__(self) -> None:
        if self.cvss_score is None:
            self.cvss_score = SEVERITY_CVSS.get(self.severity, 0.0)

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
    checks_run: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def log(self, msg: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.tool_log.append(f"[{stamp}] {msg}")

    def mark_check(self, name: str) -> None:
        if name not in self.checks_run:
            self.checks_run.append(name)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 0),
                           f.cvss_score or 0.0),
            reverse=True,
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def risk_score(self) -> float:
        """Weighted 0-100 magnitude. Higher = worse."""
        counts = self.severity_counts()
        raw = sum(SEVERITY_WEIGHT[s] * n for s, n in counts.items())
        score = 100 * (1 - (0.93 ** raw))
        return round(min(score, 100.0), 1)

    def risk_rating(self) -> str:
        """Overall rating = the highest-severity finding present (industry norm)."""
        c = self.severity_counts()
        if c["critical"]:
            return "Critical"
        if c["high"]:
            return "High"
        if c["medium"]:
            return "Medium"
        if c["low"]:
            return "Low"
        return "Informational"

    def security_grade(self) -> str:
        """A..F letter grade derived from the worst findings present."""
        c = self.severity_counts()
        if c["critical"]:
            return "F"
        if c["high"] >= 2:
            return "E"
        if c["high"] == 1:
            return "D"
        if c["medium"] >= 2:
            return "C"
        if c["medium"] == 1 or c["low"] >= 3:
            return "B"
        return "A"

    def owasp_coverage(self) -> dict[str, int]:
        """Findings grouped by their category label (OWASP Top 10)."""
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return dict(sorted(out.items(), key=lambda x: -x[1]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "normalized_url": self.normalized_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk_score": self.risk_score(),
            "risk_rating": self.risk_rating(),
            "security_grade": self.security_grade(),
            "severity_counts": self.severity_counts(),
            "owasp_coverage": self.owasp_coverage(),
            "checks_run": self.checks_run,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "meta": self.meta,
            "tool_log": self.tool_log,
            "errors": self.errors,
        }
