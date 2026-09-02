from scapy.all import IP, TCP, wrpcap


packets = []

base_time = 3000.0


for index in range(15):

    packet = (
        IP(
            src="192.168.1.60",
            dst="192.168.1.100"
        )
        /
        TCP(
            sport=41000 + index,
            dport=80,
            flags="S"
        )
    )

    packet.time = base_time + index * 0.2

    packets.append(packet)


wrpcap(
    "data/test_pcaps/syn_scan.pcap",
    packets
)


print("SYN Scan test PCAP oluşturuldu.")
print("Paket sayısı:", len(packets))