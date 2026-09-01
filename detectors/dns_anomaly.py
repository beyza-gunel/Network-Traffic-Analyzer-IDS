from collections import defaultdict


def detect_dns_anomaly(
    packets,
    query_threshold=20,
    domain_length_threshold=50
):

    alerts = []

    source_dns_count = defaultdict(int)
    domain_count = defaultdict(int)

    long_domains_seen = set()

    for packet in packets:

        dns_query = packet.get("dns_query")

        if not dns_query:
            continue

        src_ip = packet.get("src_ip")

        if src_ip:
            source_dns_count[src_ip] += 1

        domain_count[dns_query] += 1

        if len(dns_query) >= domain_length_threshold:

            key = (
                src_ip,
                dns_query
            )

            if key not in long_domains_seen:

                alerts.append({
                    "type": "DNS_ANOMALY",
                    "source_ip": src_ip,
                    "risk_score": 6,
                    "reason": (
                        f"Olağandışı uzun DNS sorgusu: "
                        f"{len(dns_query)} karakter"
                    )
                })

                long_domains_seen.add(key)

    for src_ip, count in source_dns_count.items():

        if count >= query_threshold:

            alerts.append({
                "type": "DNS_ANOMALY",
                "source_ip": src_ip,
                "risk_score": 6,
                "reason": (
                    f"Toplam {count} DNS sorgusu gönderildi"
                )
            })

    for domain, count in domain_count.items():

        if count >= query_threshold:

            alerts.append({
                "type": "DNS_ANOMALY",
                "source_ip": None,
                "risk_score": 6,
                "reason": (
                    f"{domain} alan adına "
                    f"{count} DNS sorgusu gönderildi"
                )
            })

    return alerts