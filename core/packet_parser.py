from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, rdpcap


def parse_packet(packet):

    packet_data = {
        "timestamp": float(packet.time),
        "packet_size": len(packet),

        "src_ip": None,
        "dst_ip": None,

        "protocol": "OTHER",

        "src_port": None,
        "dst_port": None,

        "tcp_flags": None,

        "dns_query": None
    }

    # -----------------------------
    # IP BİLGİLERİ
    # -----------------------------

    if packet.haslayer(IP):

        packet_data["src_ip"] = packet[IP].src
        packet_data["dst_ip"] = packet[IP].dst

    # -----------------------------
    # TCP
    # -----------------------------

    if packet.haslayer(TCP):

        packet_data["protocol"] = "TCP"

        packet_data["src_port"] = packet[TCP].sport
        packet_data["dst_port"] = packet[TCP].dport

        packet_data["tcp_flags"] = str(packet[TCP].flags)

    # -----------------------------
    # UDP
    # -----------------------------

    elif packet.haslayer(UDP):

        packet_data["protocol"] = "UDP"

        packet_data["src_port"] = packet[UDP].sport
        packet_data["dst_port"] = packet[UDP].dport

    # -----------------------------
    # ICMP
    # -----------------------------

    elif packet.haslayer(ICMP):

        packet_data["protocol"] = "ICMP"

    # -----------------------------
    # DNS
    # -----------------------------

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        try:

            query = packet[DNSQR].qname

            if isinstance(query, bytes):
                query = query.decode(errors="ignore")

            packet_data["dns_query"] = query.rstrip(".")

        except Exception:

            packet_data["dns_query"] = None

    return packet_data


def load_pcap(file_path):

    try:

        packets = rdpcap(file_path)

        parsed_packets = []

        for packet in packets:

            try:

                parsed_packet = parse_packet(packet)

                parsed_packets.append(parsed_packet)

            except Exception as error:

                print("Bir paket işlenemedi:", error)

        return parsed_packets

    except Exception as error:

        print("PCAP dosyası okunurken hata oluştu:")
        print(error)

        return []