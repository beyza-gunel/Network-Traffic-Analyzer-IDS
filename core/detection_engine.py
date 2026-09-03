from detectors.port_scan import detect_port_scan
from detectors.syn_scan import detect_syn_scan
from detectors.icmp_flood import detect_icmp_flood
from detectors.unusual_port import detect_unusual_port_activity
from detectors.dns_anomaly import detect_dns_anomaly
from detectors.traffic_burst import detect_traffic_burst
from detectors.syn_flood import detect_syn_flood
from detectors.smurf import detect_smurf_attack
from detectors.arp_spoofing import detect_arp_spoofing
from detectors.deauth import detect_deauth_attack
from detectors.disassociation import detect_disassociation_attack


def run_detection(packets):

    alerts = []

    alerts.extend(
        detect_deauth_attack(packets)
    )

    alerts.extend(
        detect_disassociation_attack(packets)
    )

    alerts.extend(
        detect_syn_flood(packets)
    )

    alerts.extend(
        detect_port_scan(packets)
    )

    alerts.extend(
        detect_syn_scan(packets)
    )

    alerts.extend(
        detect_smurf_attack(packets)
    )

    alerts.extend(
        detect_arp_spoofing(packets)
    )

    alerts.extend(
        detect_icmp_flood(packets)
    )

    alerts.extend(
        detect_unusual_port_activity(packets)
    )

    alerts.extend(
        detect_dns_anomaly(packets)
    )

    alerts.extend(
        detect_traffic_burst(packets)
    )

    return alerts