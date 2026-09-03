from detectors.rogue_ap import detect_rogue_ap


def detect_evil_twin(
    packets,
    deauth_threshold=1000,
    rogue_threshold=2
):

    # Rogue AP davranışlarını mevcut
    # detector üzerinden al.
    rogue_alerts = detect_rogue_ap(
        packets
    )

    disconnect_count = 0

    for packet in packets:

        if (
            packet.get("wlan_type") == 0
            and packet.get("wlan_subtype") in {10, 12}
        ):
            disconnect_count += 1

    # Evil Twin davranışı:
    # birden fazla şüpheli AP +
    # yoğun istemci koparma aktivitesi
    if (
        len(rogue_alerts) >= rogue_threshold
        and disconnect_count >= deauth_threshold
    ):

        suspicious_networks = []

        for alert in rogue_alerts:

            for evidence in alert.get(
                "evidence",
                []
            ):

                if evidence.startswith(
                    "SSID:"
                ):
                    suspicious_networks.append(
                        evidence
                    )

        return [{
            "type": "EVIL_TWIN",
            "source_ip": None,
            "risk_score": 12,
            "packet_count": disconnect_count,

            "reason": (
                "Birden fazla şüpheli kablosuz erişim "
                "noktası ile yoğun Deauthentication/"
                "Disassociation aktivitesi birlikte "
                "tespit edildi"
            ),

            "evidence": [
                (
                    "Şüpheli Rogue AP olayı: "
                    f"{len(rogue_alerts)}"
                ),
                (
                    "Deauth/Disassociation frame sayısı: "
                    f"{disconnect_count}"
                ),
                *suspicious_networks[:5]
            ]
        }]

    return []