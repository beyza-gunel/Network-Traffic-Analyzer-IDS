from collections import defaultdict


def detect_deauth_attack(
    packets,
    packet_threshold=10,
    time_window=10
):
    activity = defaultdict(list)

    for packet in packets:

        if packet.get("wlan_type") != 0:
            continue

        # 802.11 subtype 12 = Deauthentication
        if packet.get("wlan_subtype") != 12:
            continue

        source_mac = packet.get("wlan_addr2")
        destination_mac = packet.get("wlan_addr1")
        bssid = packet.get("wlan_addr3")
        timestamp = packet.get("timestamp")

        if (
            not source_mac
            or not destination_mac
            or timestamp is None
        ):
            continue

        source_mac = source_mac.lower()
        destination_mac = destination_mac.lower()

        # Aynı iki cihaz arasındaki çift yönlü Deauth
        # trafiğini tek saldırı olayı olarak birleştiriyoruz.
        mac_pair = tuple(
            sorted(
                (
                    source_mac,
                    destination_mac
                )
            )
        )

        key = (
            mac_pair,
            bssid
        )

        activity[key].append(
            float(timestamp)
        )

    alerts = []

    for key, timestamps in activity.items():

        mac_pair, bssid = key

        timestamps.sort()

        left = 0

        best_count = 0
        best_start = None
        best_end = None

        for right in range(len(timestamps)):

            while (
                timestamps[right]
                - timestamps[left]
                > time_window
            ):
                left += 1

            current_count = (
                right - left + 1
            )

            if current_count > best_count:

                best_count = current_count
                best_start = timestamps[left]
                best_end = timestamps[right]

        if best_count < packet_threshold:
            continue

        first_mac, second_mac = mac_pair

        alerts.append({
            "type": "DEAUTH_ATTACK",

            "source_ip": None,

            "risk_score": 10,

            "first_seen": best_start,
            "last_seen": best_end,

            "packet_count": best_count,

            "reason": (
                f"{time_window} saniye içinde "
                f"{best_count} Deauthentication frame "
                "tespit edildi"
            ),

            "evidence": [
                f"MAC 1: {first_mac}",
                f"MAC 2: {second_mac}",
                f"BSSID: {bssid}",
                f"Deauth frame sayısı: {best_count}"
            ]
        })

    return alerts