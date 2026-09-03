from utils.runtime_env import configure_runtime

configure_runtime()

from scapy.all import (
    Ether,
    ARP,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    rdpcap
)


def parse_packet(packet):

    packet_data = {
        # Ethernet / MAC
        "src_mac": None,
        "dst_mac": None,

        # ARP
        "arp_opcode": None,
        "arp_sender_ip": None,
        "arp_sender_mac": None,
        "arp_target_ip": None,
        "arp_target_mac": None,

        # ICMP
        "icmp_type": None,
        "icmp_code": None,

        # Genel paket bilgileri
        "timestamp": float(packet.time),
        "packet_size": len(packet),

        # IP
        "src_ip": None,
        "dst_ip": None,

        # Protokol
        "protocol": "OTHER",

        # TCP / UDP portları
        "src_port": None,
        "dst_port": None,

        # TCP
        "tcp_flags": None,

        # DNS
        "dns_query": None
    }

    # =========================================================
    # ETHERNET / MAC BİLGİLERİ
    # =========================================================

    if packet.haslayer(Ether):

        packet_data["src_mac"] = (
            packet[Ether].src
        )

        packet_data["dst_mac"] = (
            packet[Ether].dst
        )

    # =========================================================
    # IP BİLGİLERİ
    # =========================================================

    if packet.haslayer(IP):

        packet_data["src_ip"] = (
            packet[IP].src
        )

        packet_data["dst_ip"] = (
            packet[IP].dst
        )

    # =========================================================
    # ARP
    # =========================================================

    if packet.haslayer(ARP):

        packet_data["protocol"] = "ARP"

        packet_data["arp_opcode"] = int(
            packet[ARP].op
        )

        packet_data["arp_sender_ip"] = (
            packet[ARP].psrc
        )

        packet_data["arp_sender_mac"] = (
            packet[ARP].hwsrc
        )

        packet_data["arp_target_ip"] = (
            packet[ARP].pdst
        )

        packet_data["arp_target_mac"] = (
            packet[ARP].hwdst
        )

        # ARP paketlerinde normal IP katmanı bulunmadığı için
        # genel kaynak/hedef IP alanlarını da ARP bilgilerinden
        # dolduruyoruz.
        packet_data["src_ip"] = (
            packet[ARP].psrc
        )

        packet_data["dst_ip"] = (
            packet[ARP].pdst
        )

    # =========================================================
    # TCP
    # =========================================================

    elif packet.haslayer(TCP):

        packet_data["protocol"] = "TCP"

        packet_data["src_port"] = (
            packet[TCP].sport
        )

        packet_data["dst_port"] = (
            packet[TCP].dport
        )

        packet_data["tcp_flags"] = str(
            packet[TCP].flags
        )

    # =========================================================
    # UDP
    # =========================================================

    elif packet.haslayer(UDP):

        packet_data["protocol"] = "UDP"

        packet_data["src_port"] = (
            packet[UDP].sport
        )

        packet_data["dst_port"] = (
            packet[UDP].dport
        )

    # =========================================================
    # ICMP
    # =========================================================

    elif packet.haslayer(ICMP):

        packet_data["protocol"] = "ICMP"

        packet_data["icmp_type"] = int(
            packet[ICMP].type
        )

        packet_data["icmp_code"] = int(
            packet[ICMP].code
        )

    # =========================================================
    # DNS
    # =========================================================

    if (
        packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
    ):

        try:

            query = packet[DNSQR].qname

            if isinstance(query, bytes):

                query = query.decode(
                    errors="ignore"
                )

            packet_data["dns_query"] = (
                query.rstrip(".")
            )

        except Exception:

            packet_data["dns_query"] = None

    return packet_data


def load_pcap(file_path):

    try:

        packets = rdpcap(
            file_path
        )

        parsed_packets = []

        for packet in packets:

            try:

                parsed_packet = (
                    parse_packet(packet)
                )

                parsed_packets.append(
                    parsed_packet
                )

            except Exception as error:

                print(
                    "Bir paket işlenemedi:",
                    error
                )

        return parsed_packets

    except Exception as error:

        print(
            "PCAP dosyası okunurken "
            "hata oluştu:"
        )

        print(error)

        return []