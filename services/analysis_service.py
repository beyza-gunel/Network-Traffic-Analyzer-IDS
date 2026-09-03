import os
import time

from core.packet_parser import load_pcap
from core.traffic_analyzer import analyze_traffic
from core.detection_engine import run_detection
from core.risk_engine import calculate_risk

from models.alert import Alert
from models.analysis_result import AnalysisResult

def convert_alert(alert_data):
    risk_score = alert_data.get("risk_score", 0)

    if risk_score >= 10:
        severity = "HIGH"
    elif risk_score >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return Alert(
        alert_type=alert_data.get(
            "type",
            "UNKNOWN"
        ),
        severity=severity,
        risk_score=risk_score,
        confidence=0.70,
        reason=alert_data.get(
            "reason",
            "Açıklama bulunamadı."
        ),
        source_ip=alert_data.get(
            "source_ip"
        )
    )

class AnalysisService:

    def analyze(self, file_path):
        start_time = time.perf_counter()

        packets = load_pcap(file_path)

        if not packets:
            raise ValueError(
                "PCAP dosyasından analiz edilebilir paket okunamadı."
            )

        statistics = analyze_traffic(
            packets
        )

        raw_alerts = run_detection(
            packets
        )

        risk = calculate_risk(
            raw_alerts
        )

        alerts = [
            convert_alert(alert)
            for alert in raw_alerts
        ]

        end_time = time.perf_counter()

        analysis_duration = (
            end_time - start_time
        )

        result = AnalysisResult(
            file_path=file_path,
            file_name=os.path.basename(
                file_path
            ),
            total_packets=len(packets),
            total_bytes=statistics.get(
                "total_bytes",
                0
            ),
            packets=packets,
            statistics=statistics,
            alerts=alerts,
            risk_score=risk.get(
                "score",
                0
            ),
            risk_level=risk.get(
                "level",
                "LOW"
            ),
            analysis_duration=analysis_duration
        )

        return result