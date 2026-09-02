from scapy.all import (
    IP,
    UDP,
    DNS,
    DNSQR,
    wrpcap
)


packets = []

base_time = 5000.0


long_domain = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ".example.com"
)


for index in range(5):

    packet = (
        IP(
            src="192.168.1.80",
            dst="8.8.8.8"
        )
        /
        UDP(
            sport=53000 + index,
            dport=53
        )
        /
        DNS(
            rd=1,
            qd=DNSQR(
                qname=long_domain
            )
        )
    )

    packet.time = base_time + index * 0.5

    packets.append(packet)


wrpcap(
    "data/test_pcaps/dns_anomaly.pcap",
    packets
)


print("DNS Anomaly test PCAP oluşturuldu.")
print("Paket sayısı:", len(packets))
print("Test domain:", long_domain)
print("Domain uzunluğu:", len(long_domain))