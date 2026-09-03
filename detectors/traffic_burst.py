from collections import defaultdict
from statistics import median


def detect_traffic_burst(
    packets,
    interval=1,
    minimum_packets=20,
    burst_multiplier=5
):
    buckets = defaultdict(int)

    for packet in packets:

        timestamp = packet.get(
            "timestamp"
        )

        if timestamp is None:
            continue

        bucket = int(
            float(timestamp) // interval
        )

        buckets[bucket] += 1

    if len(buckets) < 2:
        return []

    packet_counts = list(
        buckets.values()
    )

    baseline = median(
        packet_counts
    )

    # Baseline sıfır olamaz ama güvenlik için.
    baseline = max(
        baseline,
        1
    )

    threshold = max(
        minimum_packets,
        baseline * burst_multiplier
    )

    suspicious_buckets = [
        (bucket, count)
        for bucket, count
        in sorted(buckets.items())
        if count >= threshold
    ]

    if not suspicious_buckets:
        return []

    # Aynı PCAP içindeki burst noktalarını
    # tek bir özet güvenlik olayı haline getir.
    first_bucket = (
        suspicious_buckets[0][0]
    )

    last_bucket = (
        suspicious_buckets[-1][0]
    )

    peak_bucket, peak_count = max(
        suspicious_buckets,
        key=lambda item: item[1]
    )

    total_burst_packets = sum(
        count
        for _, count
        in suspicious_buckets
    )

    return [{
        "type": "TRAFFIC_BURST",

        "risk_score": 8,

        "first_seen": (
            first_bucket * interval
        ),

        "last_seen": (
            (last_bucket + 1)
            * interval
        ),

        "packet_count": (
            total_burst_packets
        ),

        "reason": (
            f"{len(suspicious_buckets)} "
            "olağandışı trafik zaman dilimi "
            "tespit edildi. "
            f"En yoğun zaman diliminde "
            f"{peak_count} paket görüldü. "
            f"Normal temel seviye: "
            f"{baseline:.1f} paket."
        ),

        "evidence": [
            (
                "Olağandışı zaman dilimi sayısı: "
                f"{len(suspicious_buckets)}"
            ),
            (
                "En yüksek paket sayısı: "
                f"{peak_count}"
            ),
            (
                "Temel trafik seviyesi: "
                f"{baseline:.1f}"
            ),
            (
                "Burst paket toplamı: "
                f"{total_burst_packets}"
            )
        ]
    }]