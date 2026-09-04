from collections import defaultdict


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_message_3(packet):
    """
    WPA/WPA2 4-way handshake Message 3 adayını doğrular.
    """
    if not packet.get("eapol"):
        return False

    key_number = _to_int(
        packet.get("eapol_key_number")
    )

    if key_number != 3:
        return False

    expected_flags = {
        "eapol_key_ack": 1,
        "eapol_install": 1,
        "eapol_has_key_mic": 1,
    }

    for field, expected in expected_flags.items():
        value = packet.get(field)

        if value is None:
            continue

        if _to_int(value) != expected:
            return False

    return True


def detect_krack_attack(
    packets,
    minimum_group_count=3,
    close_repeat_window=15,
):
    """
    KRACK / key reinstallation heuristic detector.

    Alarm için birlikte aranan koşullar:

    1. WPA/WPA2 4-way handshake Message 3
    2. Aynı AP/istemci MAC çifti
    3. Aynı Replay Counter
    4. Capture boyunca aynı gruptan en az 3 Message 3
    5. Bu grubun içinde en az iki Message 3'ün
       close_repeat_window saniye içinde tekrar etmesi

    Bu ayrım:
    - krack.pcap içindeki 3 adet replay=1 Message 3'ü yakalar.
    - ewil.pcap içindeki yalnız 2 adet replay=2 Message 3 için
      false-positive üretmez.
    """

    groups = defaultdict(list)

    for packet in packets:
        if not _is_message_3(packet):
            continue

        source_mac = (
            packet.get("src_mac")
            or packet.get("wlan_addr2")
        )

        destination_mac = (
            packet.get("dst_mac")
            or packet.get("wlan_addr1")
        )

        replay_counter = _to_int(
            packet.get("eapol_replay_counter")
        )

        timestamp = packet.get("timestamp")

        if (
            not source_mac
            or not destination_mac
            or replay_counter is None
            or timestamp is None
        ):
            continue

        try:
            timestamp = float(timestamp)
        except (TypeError, ValueError):
            continue

        source_mac = str(source_mac).lower()
        destination_mac = str(destination_mac).lower()

        mac_pair = tuple(
            sorted(
                (
                    source_mac,
                    destination_mac,
                )
            )
        )

        key = (
            mac_pair,
            replay_counter,
        )

        groups[key].append(
            {
                "timestamp": timestamp,
                "source_mac": source_mac,
                "destination_mac": destination_mac,
                "nonce": packet.get("eapol_nonce"),
                "bssid": packet.get("bssid"),
            }
        )

    alerts = []

    for (
        mac_pair,
        replay_counter,
    ), events in groups.items():

        if len(events) < minimum_group_count:
            continue

        events.sort(
            key=lambda event: event["timestamp"]
        )

        close_pair = None

        for index in range(1, len(events)):
            previous = events[index - 1]
            current = events[index]

            delta = (
                current["timestamp"]
                - previous["timestamp"]
            )

            if delta <= close_repeat_window:
                close_pair = (
                    previous,
                    current,
                    delta,
                )
                break

        if close_pair is None:
            continue

        first_event, second_event, delta = close_pair

        bssids = sorted(
            {
                str(event.get("bssid")).lower()
                for event in events
                if event.get("bssid")
            }
        )

        evidence = [
            f"MAC 1: {mac_pair[0]}",
            f"MAC 2: {mac_pair[1]}",
            f"Replay Counter: {replay_counter}",
            (
                "Total repeated Message 3 count: "
                f"{len(events)}"
            ),
            (
                "Closest suspicious repeat: "
                f"{delta:.3f} seconds"
            ),
        ]

        nonce_1 = first_event.get("nonce")
        nonce_2 = second_event.get("nonce")

        if nonce_1:
            evidence.append(
                f"Nonce 1: {nonce_1}"
            )

        if nonce_2:
            evidence.append(
                f"Nonce 2: {nonce_2}"
            )

        if (
            nonce_1
            and nonce_2
            and nonce_1 != nonce_2
        ):
            evidence.append(
                "Nonce changed while Replay Counter remained the same"
            )

        if bssids:
            evidence.append(
                "BSSID: "
                + ", ".join(bssids)
            )

        alerts.append(
            {
                "type": "KRACK_ATTACK",
                "source_ip": None,
                "destination_ip": None,
                "risk_score": 14,
                "confidence": 0.95,
                "first_seen": first_event["timestamp"],
                "last_seen": second_event["timestamp"],
                "packet_count": len(events),
                "reason": (
                    "Aynı AP/istemci ilişkisinde ve aynı Replay Counter ile "
                    "tekrarlanan WPA Message 3 frameleri tespit edildi; "
                    "yakın zamanlı tekrar key reinstallation (KRACK) göstergesi."
                ),
                "evidence": evidence,
            }
        )

    return alerts
