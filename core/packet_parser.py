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
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    PcapReader
)

from scapy.layers.eap import (
    EAPOL,
    EAPOL_KEY
)


def parse_packet(packet):

    packet_data = {
        "wlan_type": None,
        "wlan_subtype": None,
        "wlan_protected": None,

        "wlan_addr1": None,
        "wlan_addr2": None,
        "wlan_addr3": None,

        "bssid": None,
        "ssid": None,
        "wifi_channel": None,

        "eapol": False,
        "eapol_replay_counter": None,
        "eapol_nonce": None,
        "eapol_key_number": None,
        "eapol_key_ack": None,
        "eapol_install": None,
        "eapol_secure": None,
        "eapol_has_key_mic": None,

        "src_mac": None,
        "dst_mac": None,

        "arp_opcode": None,
        "arp_sender_ip": None,
        "arp_sender_mac": None,
        "arp_target_ip": None,
        "arp_target_mac": None,

        "icmp_type": None,
        "icmp_code": None,

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

    # -------------------------------------------------
    # ETHERNET
    # -------------------------------------------------

    ether = packet.getlayer(Ether)

    if ether is not None:
        packet_data["src_mac"] = ether.src
        packet_data["dst_mac"] = ether.dst

    # -------------------------------------------------
    # 802.11
    # -------------------------------------------------

    dot11 = packet.getlayer(Dot11)

    if dot11 is not None:

        wlan_type = int(dot11.type)
        wlan_subtype = int(dot11.subtype)

        packet_data["wlan_type"] = wlan_type
        packet_data["wlan_subtype"] = wlan_subtype

        packet_data["wlan_addr1"] = dot11.addr1
        packet_data["wlan_addr2"] = dot11.addr2
        packet_data["wlan_addr3"] = dot11.addr3

        packet_data["src_mac"] = (
            dot11.addr2
            or packet_data["src_mac"]
        )

        packet_data["dst_mac"] = (
            dot11.addr1
            or packet_data["dst_mac"]
        )

        packet_data["bssid"] = dot11.addr3

        try:
            packet_data["wlan_protected"] = bool(
                int(dot11.FCfield) & 0x40
            )
        except Exception:
            pass

        # Beacon ise SSID çıkar.
        # Her Wi-Fi paketinde Beacon aramıyoruz.
        if wlan_type == 0 and wlan_subtype == 8:

            element = packet.getlayer(Dot11Elt)

            while element is not None:

                if element.ID == 0:

                    try:
                        packet_data["ssid"] = (
                            element.info.decode(
                                errors="ignore"
                            )
                        )
                    except Exception:
                        packet_data["ssid"] = str(
                            element.info
                        )

                    break

                element = element.payload.getlayer(
                    Dot11Elt
                )

        # RadioTap kanalı yalnız Wi-Fi paketinde işle.
        radiotap = packet.getlayer(RadioTap)

        if radiotap is not None:

            try:

                frequency = (
                    radiotap.ChannelFrequency
                )

                if frequency:

                    frequency = int(frequency)

                    if 2412 <= frequency <= 2472:
                        packet_data["wifi_channel"] = (
                            (frequency - 2407) // 5
                        )

                    elif frequency == 2484:
                        packet_data["wifi_channel"] = 14

            except Exception:
                pass

    # -------------------------------------------------
    # EAPOL
    # -------------------------------------------------

    eapol = packet.getlayer(EAPOL)

    if eapol is not None:

        packet_data["eapol"] = True

        key_layer = packet.getlayer(
            EAPOL_KEY
        )

        if key_layer is not None:

            try:

                packet_data[
                    "eapol_replay_counter"
                ] = int(
                    key_layer.key_replay_counter
                )

                nonce = key_layer.key_nonce

                if nonce:
                    packet_data[
                        "eapol_nonce"
                    ] = nonce.hex()

                packet_data[
                    "eapol_key_number"
                ] = int(
                    key_layer.guess_key_number()
                )

                packet_data[
                    "eapol_key_ack"
                ] = int(
                    key_layer.key_ack
                )

                packet_data[
                    "eapol_install"
                ] = int(
                    key_layer.install
                )

                packet_data[
                    "eapol_secure"
                ] = int(
                    key_layer.secure
                )

                packet_data[
                    "eapol_has_key_mic"
                ] = int(
                    key_layer.has_key_mic
                )

            except Exception:
                pass

    # -------------------------------------------------
    # ARP
    # -------------------------------------------------

    arp = packet.getlayer(ARP)

    if arp is not None:

        packet_data["protocol"] = "ARP"

        packet_data["arp_opcode"] = int(
            arp.op
        )

        packet_data["arp_sender_ip"] = arp.psrc
        packet_data["arp_sender_mac"] = arp.hwsrc
        packet_data["arp_target_ip"] = arp.pdst
        packet_data["arp_target_mac"] = arp.hwdst

        packet_data["src_ip"] = arp.psrc
        packet_data["dst_ip"] = arp.pdst

        return packet_data

    # -------------------------------------------------
    # IP
    # -------------------------------------------------

    ip_layer = packet.getlayer(IP)

    if ip_layer is not None:

        packet_data["src_ip"] = (
            ip_layer.src
        )

        packet_data["dst_ip"] = (
            ip_layer.dst
        )

    # -------------------------------------------------
    # TCP
    # -------------------------------------------------

    tcp = packet.getlayer(TCP)

    if tcp is not None:

        packet_data["protocol"] = "TCP"
        packet_data["src_port"] = tcp.sport
        packet_data["dst_port"] = tcp.dport
        packet_data["tcp_flags"] = str(
            tcp.flags
        )

    else:

        # ---------------------------------------------
        # UDP
        # ---------------------------------------------

        udp = packet.getlayer(UDP)

        if udp is not None:

            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = udp.sport
            packet_data["dst_port"] = udp.dport

        else:

            # -----------------------------------------
            # ICMP
            # -----------------------------------------

            icmp = packet.getlayer(ICMP)

            if icmp is not None:

                packet_data["protocol"] = "ICMP"

                packet_data["icmp_type"] = int(
                    icmp.type
                )

                packet_data["icmp_code"] = int(
                    icmp.code
                )

    # -------------------------------------------------
    # DNS
    # -------------------------------------------------

    if packet_data["protocol"] in {
        "UDP",
        "TCP"
    }:

        dns = packet.getlayer(DNS)

        if dns is not None:

            dnsqr = packet.getlayer(
                DNSQR
            )

            if dnsqr is not None:

                try:

                    query = dnsqr.qname

                    if isinstance(
                        query,
                        bytes
                    ):

                        query = query.decode(
                            errors="ignore"
                        )

                    packet_data[
                        "dns_query"
                    ] = query.rstrip(".")

                except Exception:
                    pass

    return packet_data


def load_pcap(file_path):

    parsed_packets = []

    try:

        with PcapReader(file_path) as pcap_reader:

            for packet_number, packet in enumerate(
                pcap_reader,
                start=1
            ):

                try:

                    parsed_packets.append(
                        parse_packet(packet)
                    )

                except Exception as error:

                    print(
                        "Bir paket işlenemedi:",
                        error
                    )

                if packet_number % 10000 == 0:

                    print(
                        f"{packet_number} paket okundu..."
                    )

        print(
            f"PCAP okuma tamamlandı: "
            f"{len(parsed_packets)} paket"
        )

        return parsed_packets

    except Exception as error:

        print(
            "PCAP dosyası okunurken "
            "hata oluştu:",
            error
        )

        return []