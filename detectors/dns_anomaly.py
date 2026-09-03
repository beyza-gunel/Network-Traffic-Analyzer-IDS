from collections import defaultdict


IGNORED_DOMAIN_SUFFIXES = (
    ".local",
    ".localdomain"
)


def is_ignored_domain(domain):
    domain = domain.lower().rstrip(".")

    return domain.endswith(
        IGNORED_DOMAIN_SUFFIXES
    )


def max_events_in_window(
    timestamps,
    time_window
):
    if not timestamps:
        return 0

    timestamps = sorted(timestamps)

    left = 0
    best_count = 0

    for right in range(len(timestamps)):

        while (
            timestamps[right]
            - timestamps[left]
            > time_window
        ):
            left += 1

        current_count = (
            right - left + 1
        )

        best_count = max(
            best_count,
            current_count
        )

    return best_count


def detect_dns_anomaly(
    packets,
    source_threshold=50,
    repeated_domain_threshold=25,
    domain_length_threshold=50,
    time_window=10
):
    source_queries = defaultdict(list)
    domain_queries = defaultdict(list)

    long_domains = set()

    for packet in packets:

        domain = packet.get(
            "dns_query"
        )

        source_ip = packet.get(
            "src_ip"
        )

        timestamp = packet.get(
            "timestamp"
        )

        if (
            not domain
            or not source_ip
            or timestamp is None
        ):
            continue

        domain = (
            str(domain)
            .lower()
            .rstrip(".")
        )

        # mDNS / yerel servis keşif trafiğini
        # saldırı olarak değerlendirme.
        if is_ignored_domain(domain):
            continue

        timestamp = float(timestamp)

        source_queries[
            source_ip
        ].append(timestamp)

        domain_queries[
            (source_ip, domain)
        ].append(timestamp)

        if (
            len(domain)
            >= domain_length_threshold
        ):
            long_domains.add(
                (source_ip, domain)
            )

    alerts = []

    # Olağandışı uzun domain
    for source_ip, domain in long_domains:

        alerts.append({
            "type": "DNS_ANOMALY",
            "source_ip": source_ip,
            "risk_score": 6,
            "reason": (
                "Olağandışı uzun DNS sorgusu "
                f"tespit edildi: {domain}"
            )
        })

    # Kısa sürede aşırı DNS sorgusu
    for source_ip, timestamps in (
        source_queries.items()
    ):

        peak_count = max_events_in_window(
            timestamps,
            time_window
        )

        if peak_count >= source_threshold:

            alerts.append({
                "type": "DNS_ANOMALY",
                "source_ip": source_ip,
                "risk_score": 6,
                "reason": (
                    f"{time_window} saniye içinde "
                    f"{peak_count} DNS sorgusu "
                    "tespit edildi"
                )
            })

    # Aynı domaine aşırı sorgu
    for (
        source_ip,
        domain
    ), timestamps in domain_queries.items():

        peak_count = max_events_in_window(
            timestamps,
            time_window
        )

        if (
            peak_count
            >= repeated_domain_threshold
        ):

            alerts.append({
                "type": "DNS_ANOMALY",
                "source_ip": source_ip,
                "risk_score": 6,
                "reason": (
                    f"{time_window} saniye içinde "
                    f"{domain} alan adına "
                    f"{peak_count} sorgu gönderildi"
                )
            })

    return alerts