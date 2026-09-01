from collections import defaultdict


SUSPICIOUS_PORTS = {
    23,
    2323,
    4444,
    5555,
    6666,
    31337
}


def detect_unusual_port_activity(
    packets,
    connection_threshold=5
):

    alerts = []

    activity = defaultdict(int)

    for packet in packets:

        if packet.get("protocol") not in ("TCP", "UDP"):
            continue

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")

        if src_ip is None or dst_port is None:
            continue

        if dst_port in SUSPICIOUS_PORTS:

            key = (
                src_ip,
                dst_port
            )

            activity[key] += 1

    for (src_ip, port), count in activity.items():

        if count >= connection_threshold:

            alerts.append({
                "type": "UNUSUAL_PORT_ACTIVITY",
                "source_ip": src_ip,
                "risk_score": 4,
                "reason": (
                    f"Riskli/alışılmadık kabul edilen "
                    f"{port} portuna {count} bağlantı denemesi"
                )
            })

    return alerts