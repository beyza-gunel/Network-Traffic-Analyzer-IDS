from scapy.all import (
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    wrpcap
)


packets = []

base_time = 1000.0


# --------------------------------
# NORMAL TCP THREE-WAY HANDSHAKE
# --------------------------------

packet1 = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    /
    TCP(
        sport=50000,
        dport=80,
        flags="S"
    )
)

packet1.time = base_time
packets.append(packet1)


packet2 = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10"
    )
    /
    TCP(
        sport=80,
        dport=50000,
        flags="SA"
    )
)

packet2.time = base_time + 0.1
packets.append(packet2)


packet3 = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    /
    TCP(
        sport=50000,
        dport=80,
        flags="A"
    )
)

packet3.time = base_time + 0.2
packets.append(packet3)


# --------------------------------
# NORMAL DNS
# --------------------------------

dns_packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8"
    )
    /
    UDP(
        sport=53000,
        dport=53
    )
    /
    DNS(
        rd=1,
        qd=DNSQR(
            qname="example.com"
        )
    )
)

dns_packet.time = base_time + 1
packets.append(dns_packet)


# --------------------------------
# NORMAL ICMP
# --------------------------------

icmp_packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.1"
    )
    /
    ICMP()
)

icmp_packet.time = base_time + 2
packets.append(icmp_packet)


# --------------------------------
# PCAP DOSYASINI OLUŞTUR
# --------------------------------

wrpcap(
    "data/test_pcaps/normal_traffic.pcap",
    packets
)


print(
    "Normal trafik PCAP oluşturuldu."
)

print(
    "Paket sayısı:",
    len(packets)
)