from scapy.all import (
    IP,
    TCP,
    ICMP,
    wrpcap
)


packets = []

base_time = 6000.0


# -------------------------------------------------
# PORT SCAN + SYN SCAN
# -------------------------------------------------

for index, port in enumerate(range(20, 35)):

    packet = (
        IP(
            src="192.168.1.90",
            dst="192.168.1.100"
        )
        /
        TCP(
            sport=42000 + index,
            dport=port,
            flags="S"
        )
    )

    packet.time = base_time + index * 0.1

    packets.append(packet)


# -------------------------------------------------
# ICMP FLOOD
# -------------------------------------------------

for index in range(30):

    packet = (
        IP(
            src="192.168.1.91",
            dst="192.168.1.100"
        )
        /
        ICMP()
    )

    packet.time = base_time + 1 + index * 0.05

    packets.append(packet)


# -------------------------------------------------
# PCAP OLUŞTUR
# -------------------------------------------------

wrpcap(
    "data/test_pcaps/combined_attack.pcap",
    packets
)


print("Combined Attack test PCAP oluşturuldu.")
print("Toplam paket sayısı:", len(packets))