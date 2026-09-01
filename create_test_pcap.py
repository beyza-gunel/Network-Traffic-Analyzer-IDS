from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap


packets = []


# --------------------------------
# NORMAL TCP
# --------------------------------

packets.append(
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


packets.append(
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


packets.append(
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


# --------------------------------
# NORMAL DNS
# --------------------------------

packets.append(
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


# --------------------------------
# NORMAL ICMP
# --------------------------------

packets.append(
    IP(
        src="192.168.1.10",
        dst="192.168.1.1"
    )
    /
    ICMP()
)

base_time = 1000.0


for index, port in enumerate(
    range(20, 35)
):

    packet = (
        IP(
            src="192.168.1.50",
            dst="192.168.1.100"
        )
        /
        TCP(
            sport=40000 + index,
            dport=port,
            flags="S"
        )
    )

    packet.time = (
        base_time
        + index * 0.2
    )

    packets.append(packet)

print("Oluşturulan paket sayısı:", len(packets))    

wrpcap(
    "data/test_pcaps/test.pcap",
    packets
)


print("Test PCAP oluşturuldu.")