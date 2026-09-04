from utils.runtime_env import configure_runtime

configure_runtime()

from scapy.all import (
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    Raw,
    wrpcap,
)


packets = []

client = "192.168.1.10"
dns_server = "8.8.8.8"
web_server = "93.184.216.34"

base_time = 10000.0


def add(packet, offset):
    packet.time = (
        base_time
        + offset
    )
    packets.append(
        packet
    )


# ---------------------------------------------------------
# Normal DNS query
# ---------------------------------------------------------

add(
    IP(
        src=client,
        dst=dns_server,
    )
    / UDP(
        sport=53000,
        dport=53,
    )
    / DNS(
        rd=1,
        qd=DNSQR(
            qname="example.com"
        ),
    ),
    0.0,
)

# ---------------------------------------------------------
# Normal HTTP TCP handshake
# ---------------------------------------------------------

add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=51000,
        dport=80,
        flags="S",
        seq=100,
    ),
    1.0,
)

add(
    IP(
        src=web_server,
        dst=client,
    )
    / TCP(
        sport=80,
        dport=51000,
        flags="SA",
        seq=500,
        ack=101,
    ),
    1.1,
)

add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=51000,
        dport=80,
        flags="A",
        seq=101,
        ack=501,
    ),
    1.2,
)

# Normal HTTP request
http_payload = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: NetworkTrafficAnalyzer-Test\r\n"
    b"Connection: close\r\n\r\n"
)

add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=51000,
        dport=80,
        flags="PA",
        seq=101,
        ack=501,
    )
    / Raw(
        load=http_payload
    ),
    1.3,
)

# ---------------------------------------------------------
# Normal HTTPS TCP handshake
# ---------------------------------------------------------

add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=52000,
        dport=443,
        flags="S",
        seq=1000,
    ),
    3.0,
)

add(
    IP(
        src=web_server,
        dst=client,
    )
    / TCP(
        sport=443,
        dport=52000,
        flags="SA",
        seq=2000,
        ack=1001,
    ),
    3.1,
)

add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=52000,
        dport=443,
        flags="A",
        seq=1001,
        ack=2001,
    ),
    3.2,
)

# Encrypted application data placeholder.
# HTTPS content is intentionally not decrypted.
add(
    IP(
        src=client,
        dst=web_server,
    )
    / TCP(
        sport=52000,
        dport=443,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(
        load=b"\x17\x03\x03\x00\x10"
        + b"encrypted-data"
    ),
    3.3,
)


output_path = (
    "data/test_pcaps/"
    "normal_web_traffic.pcap"
)

wrpcap(
    output_path,
    packets,
)

print(
    "Normal HTTP/HTTPS test PCAP created:"
)
print(
    output_path
)
print(
    f"Packet count: {len(packets)}"
)
