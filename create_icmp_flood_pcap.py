from scapy.all import IP, ICMP, wrpcap


packets = []

base_time = 4000.0


for index in range(30):

    packet = (
        IP(
            src="192.168.1.70",
            dst="192.168.1.100"
        )
        /
        ICMP()
    )

    packet.time = base_time + index * 0.1

    packets.append(packet)


wrpcap(
    "data/test_pcaps/icmp_flood.pcap",
    packets
)


print("ICMP Flood test PCAP oluşturuldu.")
print("Paket sayısı:", len(packets))