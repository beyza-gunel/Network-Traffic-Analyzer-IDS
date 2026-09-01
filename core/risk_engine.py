def calculate_risk(alerts):

    total_score = 0

    for alert in alerts:

        score = alert.get(
            "risk_score",
            0
        )

        total_score += score

    if total_score <= 4:

        level = "LOW"

    elif total_score <= 9:

        level = "MEDIUM"

    elif total_score <= 19:

        level = "HIGH"

    else:

        level = "CRITICAL"

    return {
        "score": total_score,
        "level": level
    }