from collections import defaultdict
from collections import defaultdict, Counter

IGNORED_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff"
}


def detect_arp_spoofing(
    packets,
    minimum_mac_count=2,
    minimum_observations_per_mac=3
):
    ip_to_macs = defaultdict(set)
    observations = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "ARP":
            continue

        # Sadece ARP Reply paketlerini inceliyoruz.
        if packet.get("arp_opcode") != 2:
            continue

        sender_ip = packet.get(
            "arp_sender_ip"
        )

        sender_mac = packet.get(
            "arp_sender_mac"
        )

        timestamp = packet.get(
            "timestamp"
        )

        if (
            not sender_ip
            or not sender_mac
            or timestamp is None
        ):
            continue

        if sender_ip == "0.0.0.0":
            continue

        sender_mac = sender_mac.lower()

        if sender_mac in IGNORED_MACS:
            continue

        ip_to_macs[sender_ip].add(
            sender_mac
        )

        observations[sender_ip].append({
            "timestamp": float(timestamp),
            "mac": sender_mac
        })

    alerts = []

    for ip_address, mac_addresses in ip_to_macs.items():

        if len(mac_addresses) < minimum_mac_count:
            continue

        records = observations[
            ip_address
        ]

        mac_counts = Counter(
            item["mac"]
            for item in records
        )

        reliable_macs = {
            mac
            for mac, count in mac_counts.items()
            if count >= minimum_observations_per_mac
        }

        if len(reliable_macs) < minimum_mac_count:
            continue

        mac_list = sorted(
            reliable_macs
        )

        timestamps = [
            item["timestamp"]
            for item in records
        ]

        alerts.append({
            "type": "ARP_SPOOFING",

            "source_ip": ip_address,

            "risk_score": 12,

            "first_seen": min(timestamps),
            "last_seen": max(timestamps),

            "packet_count": len(records),

            "reason": (
                f"{ip_address} IP adresi "
                f"{len(mac_list)} farklı MAC "
                "adresiyle ARP Reply paketlerinde "
                "ilan edildi"
            ),

            "evidence": [
                f"Şüpheli IP: {ip_address}",
                (
                    "Gözlenen MAC adresleri: "
                    + ", ".join(mac_list)
                ),
                (
                    "ARP Reply gözlem sayısı: "
                    f"{len(records)}"
                )
            ]
        })

    return alerts