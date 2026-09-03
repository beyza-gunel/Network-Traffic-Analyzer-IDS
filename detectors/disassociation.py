from collections import defaultdict


def detect_disassociation_attack(
    packets,
    packet_threshold=10,
    time_window=10
):
    activity = defaultdict(list)

    for packet in packets:

        if packet.get("wlan_type") != 0:
            continue

        if packet.get("wlan_subtype") != 10:
            continue

        source_mac = packet.get("wlan_addr2")
        destination_mac = packet.get("wlan_addr1")
        bssid = packet.get("wlan_addr3")
        timestamp = packet.get("timestamp")

        if not source_mac or timestamp is None:
            continue

        key = (
            source_mac,
            destination_mac,
            bssid
        )

        activity[key].append(
            float(timestamp)
        )

    alerts = []

    for key, timestamps in activity.items():

        source_mac, destination_mac, bssid = key

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

            current_count = right - left + 1

            if current_count > best_count:
                best_count = current_count
                best_start = timestamps[left]
                best_end = timestamps[right]

        if best_count < packet_threshold:
            continue

        alerts.append({
            "type": "DISASSOCIATION_ATTACK",
            "source_ip": None,
            "risk_score": 10,
            "first_seen": best_start,
            "last_seen": best_end,
            "packet_count": best_count,

            "reason": (
                f"{time_window} saniye içinde "
                f"{best_count} Disassociation frame "
                "tespit edildi"
            ),

            "evidence": [
                f"Kaynak MAC: {source_mac}",
                f"Hedef MAC: {destination_mac}",
                f"BSSID: {bssid}",
                f"Disassociation frame sayısı: {best_count}"
            ]
        })

    return alerts