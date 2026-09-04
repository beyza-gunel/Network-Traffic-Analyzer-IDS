from __future__ import annotations

import json
from pathlib import Path

from utils.runtime_env import configure_runtime

configure_runtime()

from core.packet_parser import load_pcap
from core.traffic_analyzer import analyze_traffic
from core.detection_engine import run_detection
from core.risk_engine import calculate_risk


BASE_DIR = Path(__file__).resolve().parent


SYNTHETIC_TESTS = [
    {
        "name": "Normal Web Traffic",
        "path": "data/test_pcaps/normal_web_traffic.pcap",
        "expected_alerts": [],
        "expected_risk": {"LOW"},
    },
    {
        "name": "Port Scan",
        "path": "data/test_pcaps/port_scan.pcap",
        "expected_alerts": ["PORT_SCAN"],
        "expected_risk": {"HIGH"},
    },
    {
        "name": "SYN Scan",
        "path": "data/test_pcaps/syn_scan.pcap",
        "expected_alerts": ["SYN_SCAN"],
        "expected_risk": {"HIGH"},
    },
    {
        "name": "ICMP Flood",
        "path": "data/test_pcaps/icmp_flood.pcap",
        "expected_alerts": ["ICMP_FLOOD"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "DNS Anomaly",
        "path": "data/test_pcaps/dns_anomaly.pcap",
        "expected_alerts": ["DNS_ANOMALY"],
        "expected_risk": {"MEDIUM", "HIGH"},
    },
    {
        "name": "Traffic Burst",
        "path": "data/test_pcaps/traffic_burst.pcap",
        "expected_alerts": ["TRAFFIC_BURST"],
        "expected_risk": {"MEDIUM", "HIGH"},
    },
    {
        "name": "Combined Attack",
        "path": "data/test_pcaps/combined_attack.pcap",
        "expected_alerts": [
            "PORT_SCAN",
            "SYN_SCAN",
            "ICMP_FLOOD",
        ],
        "expected_risk": {"CRITICAL"},
    },
    {
        "name": "Disassociation",
        "path": "data/test_pcaps/disassociation.pcap",
        "expected_alerts": ["DISASSOCIATION_ATTACK"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
]


REAL_TESTS = [
    {
        "name": "Real SYN Flood",
        "path": "data/real_pcaps/syn_flood_attack.pcap",
        "expected_alerts": ["SYN_FLOOD"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real Smurf",
        "path": "data/real_pcaps/smurf_attack.pcap",
        "expected_alerts": ["SMURF_ATTACK"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real MITM / ARP Spoofing",
        "path": "data/real_pcaps/mimt.pcap",
        "expected_alerts": ["ARP_SPOOFING"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real Deauthentication",
        "path": "data/real_pcaps/deauth.pcap",
        "expected_alerts": ["DEAUTH_ATTACK"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real disauth file (actual Deauth)",
        "path": "data/real_pcaps/disauth_attack.pcap",
        "expected_alerts": ["DEAUTH_ATTACK"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real Rogue AP",
        "path": "data/real_pcaps/rogue_ap.pcap",
        "expected_alerts": ["ROGUE_AP"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real Evil Twin",
        "path": "data/real_pcaps/ewil.pcap",
        "expected_alerts": ["EVIL_TWIN"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
    {
        "name": "Real KRACK",
        "path": "data/real_pcaps/krack.pcap",
        "expected_alerts": ["KRACK_ATTACK"],
        "expected_risk": {"HIGH", "CRITICAL"},
    },
]


def run_single_test(test: dict) -> dict:
    relative_path = test["path"]
    full_path = BASE_DIR / relative_path

    if not full_path.exists():
        return {
            "name": test["name"],
            "path": relative_path,
            "status": "SKIPPED",
            "reason": "PCAP file not found",
        }

    packets = load_pcap(str(full_path))
    statistics = analyze_traffic(packets)
    alerts = run_detection(packets)
    risk = calculate_risk(alerts)

    alert_types = [
        alert.get("type", "UNKNOWN")
        for alert in alerts
    ]

    missing_alerts = [
        alert_type
        for alert_type in test["expected_alerts"]
        if alert_type not in alert_types
    ]

    risk_level = str(
        risk.get("level", "LOW")
    ).upper()

    passed = (
        not missing_alerts
        and risk_level in test["expected_risk"]
    )

    return {
        "name": test["name"],
        "path": relative_path,
        "status": "PASS" if passed else "FAIL",
        "total_packets": statistics.get(
            "total_packets",
            len(packets),
        ),
        "alerts": alert_types,
        "missing_alerts": missing_alerts,
        "risk_score": risk.get("score", 0),
        "risk_level": risk_level,
        "expected_risk": sorted(test["expected_risk"]),
    }


def main():
    print("=" * 78)
    print("NETWORK TRAFFIC ANALYZER & IDS - FINAL REGRESSION TEST")
    print("=" * 78)

    results = []

    print("\n[SYNTHETIC TESTS]")
    for test in SYNTHETIC_TESTS:
        result = run_single_test(test)
        results.append(result)

        print(
            f"{result['status']:<7} | "
            f"{result['name']:<28} | "
            f"Risk: {result.get('risk_level', '-'):<8} | "
            f"Alerts: {', '.join(result.get('alerts', [])) or '-'}"
        )

        if result["status"] == "FAIL":
            if result.get("missing_alerts"):
                print(
                    "         Missing alerts:",
                    ", ".join(result["missing_alerts"]),
                )

            print(
                "         Expected risk:",
                ", ".join(result.get("expected_risk", [])),
            )

    print("\n[REAL PCAP TESTS - OPTIONAL / NOT COMMITTED]")
    for test in REAL_TESTS:
        result = run_single_test(test)
        results.append(result)

        print(
            f"{result['status']:<7} | "
            f"{result['name']:<28} | "
            f"Risk: {result.get('risk_level', '-'):<8} | "
            f"Alerts: {', '.join(result.get('alerts', [])) or '-'}"
        )

        if result["status"] == "FAIL":
            if result.get("missing_alerts"):
                print(
                    "         Missing alerts:",
                    ", ".join(result["missing_alerts"]),
                )

            print(
                "         Expected risk:",
                ", ".join(result.get("expected_risk", [])),
            )

    output_path = BASE_DIR / "test_results.json"

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            ensure_ascii=False,
            indent=2,
        )

    passed = sum(
        1
        for result in results
        if result["status"] == "PASS"
    )

    failed = sum(
        1
        for result in results
        if result["status"] == "FAIL"
    )

    skipped = sum(
        1
        for result in results
        if result["status"] == "SKIPPED"
    )

    print("\n" + "=" * 78)
    print(
        f"PASS: {passed} | "
        f"FAIL: {failed} | "
        f"SKIPPED: {skipped}"
    )
    print(
        f"Detailed result: {output_path}"
    )
    print("=" * 78)


if __name__ == "__main__":
    main()
