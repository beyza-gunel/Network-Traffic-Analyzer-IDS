from collections import defaultdict


def detect_krack_attack(
    packets,
    retransmission_threshold=3,
    time_window=10
):

    message3_activity = defaultdict(list)

    for packet in packets:

        if not packet.get("eapol"):
            continue

        key_number = packet.get(
            "eapol_key_number"
        )

        key_ack = packet.get(
            "eapol_key_ack"
        )

        install = packet.get(
            "eapol_install"
        )

        has_mic = packet.get(
            "eapol_has_key_mic"
        )

        replay_counter = packet.get(
            "eapol_replay_counter"
        )

        source_mac = packet.get(
            "src_mac"
        )

        destination_mac = packet.get(
            "dst_mac"
        )

        timestamp = packet.get(
            "timestamp"
        )

        # WPA 4-Way Handshake Message 3
        is_message_3 = (
            key_number == 3
            or (
                key_ack == 1
                and install == 1
                and has_mic == 1
            )
        )

        if not is_message_3:
            continue

        if (
            replay_counter is None
            or not source_mac
            or not destination_mac
            or timestamp is None
        ):
            continue

        source_mac = source_mac.lower()
        destination_mac = destination_mac.lower()

        # Aynı iki cihaz arasındaki trafiği
        # tek ilişki altında topluyoruz.
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
            replay_counter
        )

        message3_activity[
            key
        ].append(
            float(timestamp)
        )

    alerts = []

    for key, timestamps in (
        message3_activity.items()
    ):

        if (
            len(timestamps)
            < retransmission_threshold
        ):
            continue

        timestamps.sort()

        left = 0
        best_count = 0
        best_start = None
        best_end = None

        for right in range(
            len(timestamps)
        ):

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

                best_count = (
                    current_count
                )

                best_start = (
                    timestamps[left]
                )

                best_end = (
                    timestamps[right]
                )

        if (
            best_count
            < retransmission_threshold
        ):
            continue

        (
            mac_pair,
            replay_counter
        ) = key

        first_mac, second_mac = (
            mac_pair
        )

        alerts.append({
            "type": "KRACK_ATTACK",

            "source_ip": None,

            "risk_score": 14,

            "first_seen": best_start,

            "last_seen": best_end,

            "packet_count": best_count,

            "reason": (
                "WPA 4-way handshake sırasında "
                "aynı Replay Counter değerine sahip "
                f"{best_count} adet EAPOL-Key "
                "Message 3 tespit edildi"
            ),

            "evidence": [
                f"MAC 1: {first_mac}",
                f"MAC 2: {second_mac}",
                (
                    "Replay Counter: "
                    f"{replay_counter}"
                ),
                (
                    "Tekrarlanan Message 3: "
                    f"{best_count}"
                )
            ]
        })

    return alerts