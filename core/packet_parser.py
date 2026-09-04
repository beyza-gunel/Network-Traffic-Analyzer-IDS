from utils.runtime_env import configure_runtime
from utils.app_logger import (
    get_logger,
    safe_file_label,
)

configure_runtime()

logger = get_logger()


class PcapReadError(
    RuntimeError
):
    pass

from scapy.all import (
    Ether,
    ARP,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    Raw,
    RadioTap,
    Dot11,
    Dot11Elt,
    PcapReader,
)

from scapy.layers.eap import (
    EAPOL,
    EAPOL_KEY,
)

try:
    from scapy.layers.http import HTTPRequest
except Exception:
    HTTPRequest = None


HTTP_PORTS = {
    80,
    8000,
    8080,
}

HTTPS_PORTS = {
    443,
    8443,
}


def _safe_decode(value):
    if value is None:
        return None

    if isinstance(
        value,
        bytes,
    ):
        return value.decode(
            errors="ignore"
        )

    return str(
        value
    )


def _parse_http_from_raw(
    packet,
    packet_data,
):
    raw_layer = packet.getlayer(
        Raw
    )

    if raw_layer is None:
        return

    try:
        payload = bytes(
            raw_layer.load
        )

        text = payload.decode(
            errors="ignore"
        )

        lines = text.split(
            "\r\n"
        )

        if lines:
            first_line = (
                lines[0].split()
            )

            if len(
                first_line
            ) >= 2:
                method = (
                    first_line[0]
                    .upper()
                )

                if method in {
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "HEAD",
                    "OPTIONS",
                    "PATCH",
                    "CONNECT",
                }:
                    packet_data[
                        "http_method"
                    ] = method

                    packet_data[
                        "http_path"
                    ] = (
                        first_line[1]
                    )

        for line in lines:
            if line.lower().startswith(
                "host:"
            ):
                packet_data[
                    "http_host"
                ] = (
                    line.split(
                        ":",
                        1,
                    )[1]
                    .strip()
                )
                break

    except Exception:
        pass



WLAN_TYPE_NAMES = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension",
}


WLAN_MANAGEMENT_SUBTYPES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
}


WLAN_CONTROL_SUBTYPES = {
    8: "Block Ack Request",
    9: "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End + CF-Ack",
}


WLAN_DATA_SUBTYPES = {
    0: "Data",
    4: "Null Data",
    8: "QoS Data",
    12: "QoS Null",
}


def _get_wlan_frame_name(
    wlan_type,
    wlan_subtype,
):
    if wlan_type == 0:
        return WLAN_MANAGEMENT_SUBTYPES.get(
            wlan_subtype,
            f"Management subtype {wlan_subtype}",
        )

    if wlan_type == 1:
        return WLAN_CONTROL_SUBTYPES.get(
            wlan_subtype,
            f"Control subtype {wlan_subtype}",
        )

    if wlan_type == 2:
        return WLAN_DATA_SUBTYPES.get(
            wlan_subtype,
            f"Data subtype {wlan_subtype}",
        )

    return (
        f"802.11 type {wlan_type} "
        f"subtype {wlan_subtype}"
    )


def parse_packet(packet):
    packet_data = {
        # -------------------------------------------------
        # 802.11 / Wi-Fi
        # -------------------------------------------------
        "wlan_type": None,
        "wlan_subtype": None,
        "wlan_protected": None,
        "wlan_frame_category": None,
        "wlan_frame_name": None,
        "wlan_addr1": None,
        "wlan_addr2": None,
        "wlan_addr3": None,
        "bssid": None,
        "ssid": None,
        "wifi_channel": None,

        # -------------------------------------------------
        # WPA / EAPOL
        # -------------------------------------------------
        "eapol": False,
        "eapol_replay_counter": None,
        "eapol_nonce": None,
        "eapol_key_number": None,
        "eapol_key_ack": None,
        "eapol_install": None,
        "eapol_secure": None,
        "eapol_has_key_mic": None,

        # -------------------------------------------------
        # Ethernet / MAC
        # -------------------------------------------------
        "src_mac": None,
        "dst_mac": None,

        # -------------------------------------------------
        # ARP
        # -------------------------------------------------
        "arp_opcode": None,
        "arp_sender_ip": None,
        "arp_sender_mac": None,
        "arp_target_ip": None,
        "arp_target_mac": None,

        # -------------------------------------------------
        # ICMP
        # -------------------------------------------------
        "icmp_type": None,
        "icmp_code": None,

        # -------------------------------------------------
        # Genel paket bilgileri
        # -------------------------------------------------
        "timestamp": float(
            packet.time
        ),
        "packet_size": len(
            packet
        ),

        # -------------------------------------------------
        # IP
        # -------------------------------------------------
        "src_ip": None,
        "dst_ip": None,

        # -------------------------------------------------
        # Transport / application
        # -------------------------------------------------
        "protocol": "OTHER",
        "application_protocol": None,

        "src_port": None,
        "dst_port": None,

        "tcp_flags": None,

        # DNS
        "dns_query": None,

        # HTTP / HTTPS
        "http_method": None,
        "http_host": None,
        "http_path": None,
        "https_detected": False,
    }

    # =========================================================
    # ETHERNET
    # =========================================================

    ether = packet.getlayer(
        Ether
    )

    if ether is not None:
        packet_data[
            "src_mac"
        ] = ether.src

        packet_data[
            "dst_mac"
        ] = ether.dst

    # =========================================================
    # IEEE 802.11 / WI-FI
    # =========================================================

    dot11 = packet.getlayer(
        Dot11
    )

    if dot11 is not None:
        wlan_type = int(
            dot11.type
        )

        wlan_subtype = int(
            dot11.subtype
        )

        packet_data[
            "wlan_type"
        ] = wlan_type

        packet_data[
            "wlan_subtype"
        ] = wlan_subtype

        packet_data[
            "protocol"
        ] = "802.11"

        packet_data[
            "wlan_frame_category"
        ] = WLAN_TYPE_NAMES.get(
            wlan_type,
            "Unknown",
        )

        packet_data[
            "wlan_frame_name"
        ] = _get_wlan_frame_name(
            wlan_type,
            wlan_subtype,
        )

        packet_data[
            "wlan_addr1"
        ] = dot11.addr1

        packet_data[
            "wlan_addr2"
        ] = dot11.addr2

        packet_data[
            "wlan_addr3"
        ] = dot11.addr3

        packet_data[
            "src_mac"
        ] = (
            dot11.addr2
            or packet_data[
                "src_mac"
            ]
        )

        packet_data[
            "dst_mac"
        ] = (
            dot11.addr1
            or packet_data[
                "dst_mac"
            ]
        )

        packet_data[
            "bssid"
        ] = dot11.addr3

        try:
            packet_data[
                "wlan_protected"
            ] = bool(
                int(
                    dot11.FCfield
                )
                & 0x40
            )
        except Exception:
            pass

        # Beacon frame ise SSID çıkar.
        if (
            wlan_type == 0
            and wlan_subtype == 8
        ):
            element = (
                packet.getlayer(
                    Dot11Elt
                )
            )

            while (
                element
                is not None
            ):
                try:
                    element_id = (
                        int(
                            element.ID
                        )
                    )
                except Exception:
                    element_id = (
                        element.ID
                    )

                if element_id == 0:
                    try:
                        packet_data[
                            "ssid"
                        ] = (
                            element.info
                            .decode(
                                errors="ignore"
                            )
                        )
                    except Exception:
                        packet_data[
                            "ssid"
                        ] = str(
                            element.info
                        )

                    break

                element = (
                    element.payload
                    .getlayer(
                        Dot11Elt
                    )
                )

        # RadioTap kanal bilgisi.
        radiotap = (
            packet.getlayer(
                RadioTap
            )
        )

        if radiotap is not None:
            try:
                frequency = (
                    radiotap
                    .ChannelFrequency
                )

                if frequency:
                    frequency = int(
                        frequency
                    )

                    if (
                        2412
                        <= frequency
                        <= 2472
                    ):
                        packet_data[
                            "wifi_channel"
                        ] = (
                            (
                                frequency
                                - 2407
                            )
                            // 5
                        )

                    elif (
                        frequency
                        == 2484
                    ):
                        packet_data[
                            "wifi_channel"
                        ] = 14

            except Exception:
                pass

    # =========================================================
    # EAPOL / WPA HANDSHAKE
    # =========================================================

    eapol = packet.getlayer(
        EAPOL
    )

    if eapol is not None:
        packet_data[
            "eapol"
        ] = True

        if (
            packet_data[
                "application_protocol"
            ]
            is None
        ):
            packet_data[
                "application_protocol"
            ] = "EAPOL"

        key_layer = (
            packet.getlayer(
                EAPOL_KEY
            )
        )

        if key_layer is not None:
            try:
                packet_data[
                    "eapol_replay_counter"
                ] = int(
                    key_layer
                    .key_replay_counter
                )

                nonce = (
                    key_layer
                    .key_nonce
                )

                if nonce:
                    packet_data[
                        "eapol_nonce"
                    ] = nonce.hex()

                packet_data[
                    "eapol_key_number"
                ] = int(
                    key_layer
                    .guess_key_number()
                )

                packet_data[
                    "eapol_key_ack"
                ] = int(
                    key_layer
                    .key_ack
                )

                packet_data[
                    "eapol_install"
                ] = int(
                    key_layer
                    .install
                )

                packet_data[
                    "eapol_secure"
                ] = int(
                    key_layer
                    .secure
                )

                packet_data[
                    "eapol_has_key_mic"
                ] = int(
                    key_layer
                    .has_key_mic
                )

            except Exception:
                pass

    # =========================================================
    # ARP
    # =========================================================

    arp = packet.getlayer(
        ARP
    )

    if arp is not None:
        packet_data[
            "protocol"
        ] = "ARP"

        packet_data[
            "application_protocol"
        ] = "ARP"

        packet_data[
            "arp_opcode"
        ] = int(
            arp.op
        )

        packet_data[
            "arp_sender_ip"
        ] = arp.psrc

        packet_data[
            "arp_sender_mac"
        ] = arp.hwsrc

        packet_data[
            "arp_target_ip"
        ] = arp.pdst

        packet_data[
            "arp_target_mac"
        ] = arp.hwdst

        packet_data[
            "src_ip"
        ] = arp.psrc

        packet_data[
            "dst_ip"
        ] = arp.pdst

        return packet_data

    # =========================================================
    # IP
    # =========================================================

    ip_layer = packet.getlayer(
        IP
    )

    if ip_layer is not None:
        packet_data[
            "src_ip"
        ] = ip_layer.src

        packet_data[
            "dst_ip"
        ] = ip_layer.dst

    # =========================================================
    # TCP
    # =========================================================

    tcp = packet.getlayer(
        TCP
    )

    if tcp is not None:
        source_port = int(
            tcp.sport
        )

        destination_port = int(
            tcp.dport
        )

        packet_data[
            "protocol"
        ] = "TCP"

        packet_data[
            "src_port"
        ] = source_port

        packet_data[
            "dst_port"
        ] = destination_port

        packet_data[
            "tcp_flags"
        ] = str(
            tcp.flags
        )

        if (
            source_port
            in HTTP_PORTS
            or destination_port
            in HTTP_PORTS
        ):
            packet_data[
                "application_protocol"
            ] = "HTTP"

        elif (
            source_port
            in HTTPS_PORTS
            or destination_port
            in HTTPS_PORTS
        ):
            packet_data[
                "application_protocol"
            ] = "HTTPS"

            packet_data[
                "https_detected"
            ] = True

    else:
        # =====================================================
        # UDP
        # =====================================================

        udp = packet.getlayer(
            UDP
        )

        if udp is not None:
            source_port = int(
                udp.sport
            )

            destination_port = int(
                udp.dport
            )

            packet_data[
                "protocol"
            ] = "UDP"

            packet_data[
                "src_port"
            ] = source_port

            packet_data[
                "dst_port"
            ] = destination_port

            if (
                source_port == 53
                or destination_port
                == 53
            ):
                packet_data[
                    "application_protocol"
                ] = "DNS"

        else:
            # =================================================
            # ICMP
            # =================================================

            icmp = packet.getlayer(
                ICMP
            )

            if icmp is not None:
                packet_data[
                    "protocol"
                ] = "ICMP"

                packet_data[
                    "application_protocol"
                ] = "ICMP"

                packet_data[
                    "icmp_type"
                ] = int(
                    icmp.type
                )

                packet_data[
                    "icmp_code"
                ] = int(
                    icmp.code
                )

    # =========================================================
    # DNS
    # =========================================================

    dns = packet.getlayer(
        DNS
    )

    if dns is not None:
        packet_data[
            "application_protocol"
        ] = "DNS"

        dnsqr = packet.getlayer(
            DNSQR
        )

        if dnsqr is not None:
            try:
                query = (
                    dnsqr.qname
                )

                query = _safe_decode(
                    query
                )

                if query:
                    packet_data[
                        "dns_query"
                    ] = (
                        query.rstrip(
                            "."
                        )
                    )

            except Exception:
                pass

    # =========================================================
    # HTTP
    # =========================================================

    if (
        packet_data[
            "application_protocol"
        ]
        == "HTTP"
    ):
        http_parsed = False

        if HTTPRequest is not None:
            try:
                http_request = (
                    packet.getlayer(
                        HTTPRequest
                    )
                )

                if (
                    http_request
                    is not None
                ):
                    packet_data[
                        "http_method"
                    ] = _safe_decode(
                        http_request
                        .Method
                    )

                    packet_data[
                        "http_host"
                    ] = _safe_decode(
                        http_request
                        .Host
                    )

                    packet_data[
                        "http_path"
                    ] = _safe_decode(
                        http_request
                        .Path
                    )

                    http_parsed = True

            except Exception:
                pass

        if not http_parsed:
            _parse_http_from_raw(
                packet,
                packet_data,
            )

    return packet_data


def load_pcap(file_path):
    parsed_packets = []

    skipped_packets = 0

    file_label = safe_file_label(
        file_path
    )

    logger.info(
        "PCAP parsing started: %s",
        file_label,
    )

    try:
        with PcapReader(
            file_path
        ) as pcap_reader:
            for (
                packet_number,
                packet,
            ) in enumerate(
                pcap_reader,
                start=1,
            ):
                try:
                    parsed_packets.append(
                        parse_packet(
                            packet
                        )
                    )

                except Exception:
                    skipped_packets += 1

                    # Paket payload'u veya hassas veri
                    # loglanmaz. Yalnız sayaç tutulur.
                    if (
                        skipped_packets
                        <= 5
                    ):
                        logger.warning(
                            "Malformed packet skipped "
                            "while parsing %s "
                            "(packet number: %d)",
                            file_label,
                            packet_number,
                        )

                if (
                    packet_number
                    % 10000
                    == 0
                ):
                    print(
                        f"{packet_number} "
                        "paket okundu..."
                    )

        print(
            "PCAP okuma tamamlandı: "
            f"{len(parsed_packets)} "
            "paket"
        )

        logger.info(
            "PCAP parsing completed: %s | "
            "parsed=%d | skipped=%d",
            file_label,
            len(
                parsed_packets
            ),
            skipped_packets,
        )

        return parsed_packets

    except Exception as error:
        logger.error(
            "PCAP parsing failed: %s | %s",
            file_label,
            type(
                error
            ).__name__,
        )

        raise PcapReadError(
            "PCAP dosyası okunamadı veya "
            "dosya yapısı bozuk."
        ) from error
