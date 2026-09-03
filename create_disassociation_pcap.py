from utils.runtime_env import configure_runtime

configure_runtime()

from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Disas,
    wrpcap
)


packets = []

base_time = 9000.0

ap_mac = "10:7b:ef:7e:8e:c0"
client_mac = "28:c2:dd:5a:43:e7"


for index in range(20):

    packet = (
        RadioTap()
        /
        Dot11(
            type=0,
            subtype=10,
            addr1=client_mac,
            addr2=ap_mac,
            addr3=ap_mac
        )
        /
        Dot11Disas(
            reason=8
        )
    )

    packet.time = (
        base_time + index * 0.2
    )

    packets.append(packet)


wrpcap(
    "data/test_pcaps/disassociation.pcap",
    packets
)


print(
    "Disassociation test PCAP oluşturuldu."
)

print(
    "Paket sayısı:",
    len(packets)
)