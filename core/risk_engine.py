"""Professional 0-100 risk correlation engine.

Detector risk_score values remain detector/rule weights.
This module converts individual alert severity plus correlation context
into a true global 0-100 risk score.
"""

SEVERITY_BASE_SCORE = {
    "LOW": 10,
    "MEDIUM": 35,
    "HIGH": 60,
    "CRITICAL": 85,
}

VALID_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _alert_type(alert):
    return str(
        alert.get("type")
        or alert.get("alert_type")
        or "UNKNOWN"
    ).upper()


def _alert_level(alert):
    severity = str(alert.get("severity") or "").upper()

    if severity in VALID_LEVELS:
        return severity

    # Backward compatibility for detectors that expose only rule weight.
    weight = _safe_int(alert.get("risk_score"), 0)

    if weight >= 12:
        return "CRITICAL"
    if weight >= 10:
        return "HIGH"
    if weight >= 5:
        return "MEDIUM"
    return "LOW"


def risk_level_from_score(score):
    score = max(0, min(100, _safe_int(score, 0)))

    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def calculate_risk(alerts):
    """Return a normalized global 0-100 risk result.

    Baseline by highest alert severity:
      LOW=10, MEDIUM=35, HIGH=60, CRITICAL=85

    Correlation:
      +5 when two or more alarms coexist
      +5 per additional distinct attack type, capped at +10

    Example:
      3 distinct HIGH alerts = 60 + 5 + 10 = 75 / CRITICAL
    """
    alerts = list(alerts or [])

    if not alerts:
        empty = []
        return {
            "score": 0,
            "level": "LOW",
            "breakdown": empty,
            "contributions": empty,
        }

    levels = [_alert_level(alert) for alert in alerts]

    highest_level = max(
        levels,
        key=lambda level: SEVERITY_BASE_SCORE[level],
    )
    base_score = SEVERITY_BASE_SCORE[highest_level]

    alert_count = len(alerts)
    unique_types = {_alert_type(alert) for alert in alerts}
    unique_type_count = len(unique_types)

    multiple_alert_bonus = 5 if alert_count >= 2 else 0
    diversity_bonus = min(
        10,
        max(0, (unique_type_count - 1) * 5),
    )

    final_score = min(
        100,
        base_score + multiple_alert_bonus + diversity_bonus,
    )
    final_level = risk_level_from_score(final_score)

    breakdown = [
        {
            "component": "severity_baseline",
            "label": "En yüksek alarm seviyesi",
            "score": base_score,
            "detail": highest_level,
        }
    ]

    if multiple_alert_bonus:
        breakdown.append(
            {
                "component": "multiple_alert_bonus",
                "label": "Çoklu alarm korelasyonu",
                "score": multiple_alert_bonus,
                "detail": f"{alert_count} alarm birlikte görüldü",
            }
        )

    if diversity_bonus:
        breakdown.append(
            {
                "component": "attack_diversity_bonus",
                "label": "Saldırı çeşitliliği",
                "score": diversity_bonus,
                "detail": f"{unique_type_count} farklı saldırı türü",
            }
        )

    breakdown.append(
        {
            "component": "final_score",
            "label": "Genel risk",
            "score": final_score,
            "detail": f"{final_level} / 100",
        }
    )

    # "contributions" is retained for compatibility with earlier
    # AnalysisService / report code.
    return {
        "score": final_score,
        "level": final_level,
        "breakdown": breakdown,
        "contributions": breakdown,
    }
