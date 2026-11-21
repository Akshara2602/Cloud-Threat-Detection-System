
def calculate_risk_score(
    severity,
    failed_attempts=0,
    suspicious_ip=False,
    privileged_action=False,
    guardduty_score=0
):

    score = 0

    severity_scores = {
        "LOW": 10,
        "MEDIUM": 30,
        "HIGH": 60,
        "CRITICAL": 85
    }

    score += severity_scores.get(severity, 0)

    if failed_attempts >= 5:
        score += 10

    if failed_attempts >= 10:
        score += 15

    if suspicious_ip:
        score += 15

    if privileged_action:
        score += 10

    if guardduty_score >= 8:
        score += 10

    return min(score, 100)


def get_risk_level(score):

    if score >= 85:
        return "CRITICAL"

    elif score >= 65:
        return "HIGH"

    elif score >= 35:
        return "MEDIUM"

    return "LOW"
