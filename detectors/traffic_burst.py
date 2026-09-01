from collections import defaultdict


def detect_traffic_burst(
    packets,
    interval=1,
    burst_multiplier=5,
    minimum_packets=20
):

    alerts = []

    buckets = defaultdict(int)

    for packet in packets:

        timestamp = packet.get("timestamp")

        if timestamp is None:
            continue

        bucket = int(timestamp // interval)

        buckets[bucket] += 1

    if len(buckets) < 2:
        return alerts

    counts = list(buckets.values())

    average = sum(counts) / len(counts)

    for bucket, count in buckets.items():

        if (
            count >= minimum_packets
            and count >= average * burst_multiplier
        ):

            alerts.append({
                "type": "TRAFFIC_BURST",
                "source_ip": None,
                "risk_score": 8,
                "reason": (
                    f"{interval} saniyelik zaman diliminde "
                    f"{count} paket görüldü. "
                    f"Ortalama: {average:.2f}"
                )
            })

    return alerts