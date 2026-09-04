import time
from pathlib import Path

from core.packet_parser import load_pcap
from core.traffic_analyzer import analyze_traffic
from core.flow_analyzer import analyze_flows
from core.detection_engine import run_detection
from core.risk_engine import calculate_risk

from models.alert import Alert
from models.analysis_result import AnalysisResult


def _severity_from_score(
    risk_score,
):
    score = int(
        risk_score
        or 0
    )

    if score >= 12:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


def _convert_alert(
    raw_alert,
):
    risk_score = int(
        raw_alert.get(
            "risk_score",
            0,
        )
        or 0
    )

    severity = (
        raw_alert.get(
            "severity"
        )
        or _severity_from_score(
            risk_score
        )
    )

    confidence = raw_alert.get(
        "confidence",
        0.80,
    )

    try:
        confidence = float(
            confidence
        )
    except (
        TypeError,
        ValueError,
    ):
        confidence = 0.80

    return Alert(
        alert_type=str(
            raw_alert.get(
                "type",
                "UNKNOWN",
            )
        ),
        severity=str(
            severity
        ),
        risk_score=risk_score,
        confidence=confidence,
        reason=str(
            raw_alert.get(
                "reason",
                "",
            )
            or ""
        ),
        source_ip=raw_alert.get(
            "source_ip"
        ),
        destination_ip=raw_alert.get(
            "destination_ip"
        ),
        source_port=raw_alert.get(
            "source_port"
        ),
        destination_port=raw_alert.get(
            "destination_port"
        ),
        first_seen=raw_alert.get(
            "first_seen"
        ),
        last_seen=raw_alert.get(
            "last_seen"
        ),
        packet_count=int(
            raw_alert.get(
                "packet_count",
                0,
            )
            or 0
        ),
        evidence=list(
            raw_alert.get(
                "evidence",
                [],
            )
            or []
        ),
    )


class AnalysisService:

    def analyze(
        self,
        file_path,
    ):
        started_at = (
            time.perf_counter()
        )

        packets = load_pcap(
            file_path
        )

        statistics = analyze_traffic(
            packets
        )

        flows = analyze_flows(
            packets
        )

        raw_alerts = run_detection(
            packets
        )

        risk = calculate_risk(
            raw_alerts
        )

        alerts = [
            _convert_alert(
                raw_alert
            )
            for raw_alert
            in raw_alerts
        ]

        analysis_duration = (
            time.perf_counter()
            - started_at
        )

        total_packets = int(
            statistics.get(
                "total_packets",
                len(
                    packets
                ),
            )
            or 0
        )

        total_bytes = int(
            statistics.get(
                "total_bytes",
                sum(
                    int(
                        packet.get(
                            "packet_size",
                            0,
                        )
                        or 0
                    )
                    for packet
                    in packets
                ),
            )
            or 0
        )

        return AnalysisResult(
            file_path=str(
                file_path
            ),
            file_name=Path(
                file_path
            ).name,
            total_packets=(
                total_packets
            ),
            total_bytes=(
                total_bytes
            ),
            packets=packets,
            statistics=statistics,
            alerts=alerts,
            flows=flows,
            risk_score=int(
                risk.get(
                    "score",
                    0,
                )
                or 0
            ),
            risk_level=str(
                risk.get(
                    "level",
                    "LOW",
                )
            ),
            risk_breakdown=list(
                risk.get(
                    "contributions",
                    [],
                )
                or []
            ),
            analysis_duration=(
                analysis_duration
            ),
        )
