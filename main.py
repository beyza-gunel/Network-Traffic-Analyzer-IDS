from core.packet_parser import load_pcap
from core.traffic_analyzer import analyze_traffic
from core.detection_engine import run_detection
from core.risk_engine import calculate_risk


def main():

    file_path = "data/test_pcaps/test.pcap"

    print("PCAP yükleniyor...")

    packets = load_pcap(file_path)

    if not packets:

        print("Paket bulunamadı veya dosya okunamadı.")
        return

    print()
    print("=== TRAFFIC STATISTICS ===")

    statistics = analyze_traffic(packets)

    for key, value in statistics.items():

        print(
            f"{key}: {value}"
        )

    print()
    print("=== DETECTION ===")

    alerts = run_detection(packets)

    if not alerts:

        print("Şüpheli trafik bulunamadı.")

    else:

        for alert in alerts:

            print()
            print("Alert:", alert["type"])
            print(
                "Source:",
                alert.get("source_ip")
            )
            print(
                "Reason:",
                alert.get("reason")
            )
            print(
                "Score:",
                alert.get("risk_score")
            )

    print()
    print("=== RISK ===")

    risk = calculate_risk(alerts)

    print("Risk Score:", risk["score"])
    print("Risk Level:", risk["level"])


if __name__ == "__main__":
    main()