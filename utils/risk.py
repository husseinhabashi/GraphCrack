#!/usr/bin/env python3
"""
Risk Scoring Utility for GraphQL Crack Engine
Calculates numeric risk scores (0–100) and labels for findings/vulnerabilities.
"""

from typing import Dict, Any

SEVERITY_BASE = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 15,
    "INFO": 5,
}

def clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))

def map_severity_label(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 15: return "LOW"
    return "INFO"

def compute_risk_score(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a numeric risk score for a single finding."""
    sev_label = (finding.get("severity") or "MEDIUM").upper()
    base = SEVERITY_BASE.get(sev_label, 40)

    exp_map = {"trivial": 1.2, "easy": 0.95, "moderate": 0.7, "hard": 0.45}
    exploitability = exp_map.get((finding.get("exploitability") or "moderate").lower(), 0.7)

    exposure_map = {"public": 1.5, "authenticated": 1.0, "internal": 0.7}
    exposure = exposure_map.get((finding.get("exposure") or "authenticated").lower(), 1.0)

    conf = finding.get("confidence")
    conf_factor = 0.7 if conf is None else max(0.2, min(1.0, float(conf)))

    raw = base * exploitability * exposure * conf_factor
    score = int(clamp(round(raw), 0, 100))
    label = map_severity_label(score)

    finding["risk_score"] = score
    finding["risk_label"] = label
    finding.setdefault("computed_risk_details", {
        "base": base,
        "exploitability": exploitability,
        "exposure": exposure,
        "confidence_factor": conf_factor,
        "raw": raw,
    })
    return finding

def aggregate_target_score(vulns):
    """Compute overall target risk score (average)."""
    if not vulns:
        return 0
    total = sum(v.get("risk_score", 0) for v in vulns)
    return int(total / len(vulns))