from scapy.all import (
    IP,
    TCP,
    wrpcap
)


packets = []

base_time = 2000.0


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
            flags="A"
        )
    )

    packet.time = (
        base_time
        + index * 0.2
    )

    packets.append(packet)


wrpcap(
    "data/test_pcaps/port_scan.pcap",
    packets
)


print(
    "Port Scan test PCAP oluşturuldu."
)

print(
    "Paket sayısı:",
    len(packets)
)