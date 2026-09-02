from scapy.all import (
    IP,
    UDP,
    wrpcap
)


packets = []

base_time = 7000.0


# -------------------------------------------------
# NORMAL TRAFİK
# 10 saniye boyunca saniyede 5 paket
# -------------------------------------------------

for second in range(10):

    for packet_index in range(5):

        packet = (
            IP(
                src="192.168.1.110",
                dst="192.168.1.120"
            )
            /
            UDP(
                sport=55000,
                dport=9999
            )
        )

        packet.time = (
            base_time
            + second
            + packet_index * 0.1
        )

        packets.append(packet)


# -------------------------------------------------
# TRAFFIC BURST
# 1 saniye içerisinde 100 paket
# -------------------------------------------------

burst_time = base_time + 10


for packet_index in range(100):

    packet = (
        IP(
            src="192.168.1.110",
            dst="192.168.1.120"
        )
        /
        UDP(
            sport=55000,
            dport=9999
        )
    )

    packet.time = (
        burst_time
        + packet_index * 0.005
    )

    packets.append(packet)


# -------------------------------------------------
# PCAP DOSYASINI OLUŞTUR
# -------------------------------------------------

wrpcap(
    "data/test_pcaps/traffic_burst.pcap",
    packets
)


print("Traffic Burst test PCAP oluşturuldu.")
print("Toplam paket sayısı:", len(packets))