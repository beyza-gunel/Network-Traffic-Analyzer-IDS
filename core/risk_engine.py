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

    # -------------------------------------------------
    # TRAFFIC BURST İLE İLİŞKİLİ ÖZEL SALDIRILAR
    # -------------------------------------------------

    burst_correlated_types = {
        "SYN_FLOOD",
        "ICMP_FLOOD",
        "SMURF_ATTACK",
        "DEAUTH_ATTACK",
        "DISASSOCIATION_ATTACK"
    }

    has_specific_burst_attack = any(
        alert.get("type") in burst_correlated_types
        for alert in alerts
    )

    # -------------------------------------------------
    # EVIL TWIN / ROGUE AP KORELASYONU
    # -------------------------------------------------

    has_evil_twin = any(
        alert.get("type") == "EVIL_TWIN"
        for alert in alerts
    )

    # -------------------------------------------------
    # RİSK HESAPLAMA
    # -------------------------------------------------

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

        # Traffic Burst başka bir saldırının
        # sonucuysa tam puan verme.
        if (
            alert_type == "TRAFFIC_BURST"
            and has_specific_burst_attack
        ):

            contribution = min(
                base_score,
                3
            )

            contribution_type = "SUPPORTING"

        # Evil Twin zaten tespit edilmişse
        # Rogue AP aynı olayın destekleyici
        # göstergesi olarak değerlendirilir.
        elif (
            alert_type == "ROGUE_AP"
            and has_evil_twin
        ):

            contribution = min(
                base_score,
                3
            )

            contribution_type = "SUPPORTING"

        # Aynı alarm türü birden fazla kez
        # oluşursa riski gereksiz şişirme.
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

    # Maksimum risk puanı
    total_score = min(
        total_score,
        100
    )

    # -------------------------------------------------
    # RİSK SEVİYESİ
    # -------------------------------------------------

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