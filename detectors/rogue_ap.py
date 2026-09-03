from collections import defaultdict, Counter
from statistics import median


def detect_rogue_ap(
    packets,
    minimum_beacons=5,
    size_difference_threshold=30
):
    networks = defaultdict(list)
    ssid_to_bssids = defaultdict(set)

    for packet in packets:

        # Beacon frame
        if (
            packet.get("wlan_type") != 0
            or packet.get("wlan_subtype") != 8
        ):
            continue

        ssid = packet.get("ssid")
        bssid = packet.get("bssid")
        channel = packet.get("wifi_channel")
        packet_size = packet.get("packet_size")
        timestamp = packet.get("timestamp")

        if (
            not ssid
            or not bssid
            or packet_size is None
        ):
            continue

        bssid = bssid.lower()

        ssid_to_bssids[ssid].add(
            bssid
        )

        networks[
            (ssid, bssid)
        ].append({
            "size": int(packet_size),
            "channel": channel,
            "timestamp": timestamp
        })

    alerts = []
    alerted = set()

    # -------------------------------------------------
    # 1. Aynı SSID/BSSID için beacon fingerprint değişimi
    # -------------------------------------------------

    for (
        ssid,
        bssid
    ), records in networks.items():

        if len(records) < minimum_beacons:
            continue

        sizes = [
            item["size"]
            for item in records
        ]

        size_counts = Counter(
            sizes
        )

        reliable_sizes = [
            size
            for size, count
            in size_counts.items()
            if count >= minimum_beacons
        ]

        channels = {
            item["channel"]
            for item in records
            if item["channel"] is not None
        }

        fingerprint_conflict = False

        if len(reliable_sizes) >= 2:

            if (
                max(reliable_sizes)
                - min(reliable_sizes)
                >= size_difference_threshold
            ):
                fingerprint_conflict = True

        if len(channels) >= 2:
            fingerprint_conflict = True

        if not fingerprint_conflict:
            continue

        key = (
            ssid,
            bssid
        )

        alerted.add(key)

        alerts.append({
            "type": "ROGUE_AP",
            "source_ip": None,
            "risk_score": 10,
            "packet_count": len(records),

            "reason": (
                f"'{ssid}' SSID'si için "
                f"{bssid} BSSID üzerinde "
                "tutarsız Beacon fingerprint "
                "tespit edildi"
            ),

            "evidence": [
                f"SSID: {ssid}",
                f"BSSID: {bssid}",
                (
                    "Beacon boyutları: "
                    + ", ".join(
                        str(x)
                        for x in sorted(
                            reliable_sizes
                        )
                    )
                ),
                (
                    "Kanallar: "
                    + ", ".join(
                        str(x)
                        for x in sorted(
                            channels
                        )
                    )
                )
            ]
        })

    # -------------------------------------------------
    # 2. Aynı SSID'yi birden fazla BSSID yayınlıyor
    #    ve belirgin Beacon fingerprint farkı var.
    # -------------------------------------------------

    for ssid, bssids in ssid_to_bssids.items():

        if len(bssids) < 2:
            continue

        bssid_medians = {}

        for bssid in bssids:

            records = networks.get(
                (ssid, bssid),
                []
            )

            if len(records) < minimum_beacons:
                continue

            bssid_medians[bssid] = median(
                item["size"]
                for item in records
            )

        if len(bssid_medians) < 2:
            continue

        values = list(
            bssid_medians.values()
        )

        if (
            max(values) - min(values)
            < size_difference_threshold
        ):
            continue

        suspicious_bssid = min(
            bssid_medians,
            key=bssid_medians.get
        )

        key = (
            ssid,
            suspicious_bssid
        )

        if key in alerted:
            continue

        alerts.append({
            "type": "ROGUE_AP",
            "source_ip": None,
            "risk_score": 10,

            "reason": (
                f"'{ssid}' SSID'si farklı "
                "BSSID'ler tarafından farklı "
                "Beacon fingerprintleriyle "
                "yayınlanıyor"
            ),

            "evidence": [
                f"SSID: {ssid}",
                (
                    "BSSID'ler: "
                    + ", ".join(
                        sorted(bssids)
                    )
                ),
                f"Şüpheli BSSID: {suspicious_bssid}"
            ]
        })

    return alerts