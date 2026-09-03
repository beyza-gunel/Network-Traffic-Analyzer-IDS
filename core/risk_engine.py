def calculate_risk(alerts):

    if not alerts:
        return {
            "score": 0,
            "level": "LOW",
            "contributions": []
        }

    total_score = 0
    contributions = []

    seen_alert_types = set()

    flood_types = {
        "SYN_FLOOD",
        "ICMP_FLOOD",
        "SMURF_ATTACK"
    }

    has_specific_flood = any(
        alert.get("type") in flood_types
        for alert in alerts
    )

    for alert in alerts:

        alert_type = alert.get(
            "type",
            "UNKNOWN"
        )

        base_score = int(
            alert.get(
                "risk_score",
                0
            )
        )

        contribution = base_score
        contribution_type = "PRIMARY"

        # Traffic Burst, başka bir flood saldırısının
        # sonucuysa tam puanla tekrar sayma.
        if (
            alert_type == "TRAFFIC_BURST"
            and has_specific_flood
        ):
            contribution = min(
                base_score,
                3
            )

            contribution_type = "SUPPORTING"

        # Aynı alarm türü tekrar ederse
        # genel risk puanını gereksiz şişirme.
        elif alert_type in seen_alert_types:

            contribution = min(
                base_score,
                2
            )

            contribution_type = "REPEATED"

        total_score += contribution

        contributions.append({
            "alert_type": alert_type,
            "base_score": base_score,
            "contribution": contribution,
            "contribution_type": contribution_type
        })

        seen_alert_types.add(
            alert_type
        )

    total_score = min(
        total_score,
        100
    )

    if total_score >= 20:
        level = "CRITICAL"

    elif total_score >= 10:
        level = "HIGH"

    elif total_score >= 5:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": total_score,
        "level": level,
        "contributions": contributions
    }