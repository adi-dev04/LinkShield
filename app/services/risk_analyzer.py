
def calculate_risk_score(findings: list, analysis_complete: bool = True) -> dict:

    if not analysis_complete:
        return {
            "risk_score": None,
            "risk_level": "inconclusive"
        }

    score = 0

    severity_weights = {
        "low": 5,
        "medium": 15,
        "high": 30,
        "critical": 50
    }

    for finding in findings:
        severity = finding.get("severity", "").lower()
        score += severity_weights.get(severity, 0)

    score = min(score, 100)

    if score <= 20:
        risk_level = "low_risk"
    elif score <= 40:
        risk_level = "suspicious"
    else:
        risk_level = "high_risk"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }
