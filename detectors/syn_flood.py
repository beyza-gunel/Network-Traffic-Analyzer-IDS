from collections import defaultdict


def detect_syn_flood(
    packets,
    syn_threshold=100,
    time_window=10,
    response_ratio_threshold=0.20
):
    syn_events = defaultdict(list)
    synack_counts = defaultdict(int)

    for packet in packets:

        if packet.get("protocol") != "TCP":
            continue

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")

        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")

        flags = packet.get("tcp_flags")
        timestamp = packet.get("timestamp")

        if not src_ip or not dst_ip or timestamp is None:
            continue

        # Bağlantı başlatan saf SYN
        if flags == "S":

            key = (
                src_ip,
                dst_ip,
                dst_port
            )

            syn_events[key].append(
                float(timestamp)
            )

        # SYN + ACK cevabı
        elif flags == "SA":

            reverse_key = (
                dst_ip,
                src_ip,
                src_port
            )

            synack_counts[reverse_key] += 1

    alerts = []

    for key, timestamps in syn_events.items():

        source_ip, destination_ip, destination_port = key

        timestamps.sort()

        left = 0

        best_count = 0
        best_start = None
        best_end = None

        for right in range(len(timestamps)):

            while (
                timestamps[right] - timestamps[left]
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

        if best_count < syn_threshold:
            continue

        total_syn = len(timestamps)

        synack_count = synack_counts.get(
            key,
            0
        )

        response_ratio = (
            synack_count / total_syn
            if total_syn > 0
            else 0
        )

        if response_ratio > response_ratio_threshold:
            continue

        alerts.append({
            "type": "SYN_FLOOD",

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "destination_port": destination_port,

            "risk_score": 12,

            "first_seen": best_start,

            "last_seen": best_end,

            "packet_count": best_count,

            "reason": (
                f"{time_window} saniye içinde "
                f"{best_count} SYN paketi "
                f"{destination_ip}:{destination_port} "
                f"hedefine gönderildi. "
                f"SYN-ACK cevap oranı: "
                f"%{response_ratio * 100:.1f}"
            ),

            "evidence": [
                f"Toplam SYN sayısı: {total_syn}",
                f"En yoğun {time_window} saniye: {best_count} SYN",
                f"SYN-ACK sayısı: {synack_count}",
                f"Hedef port: {destination_port}"
            ]
        })

    return alerts