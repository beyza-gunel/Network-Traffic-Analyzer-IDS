from dataclasses import dataclass, field

from models.alert import Alert


@dataclass
class AnalysisResult:
    file_path: str
    file_name: str

    total_packets: int = 0
    total_bytes: int = 0

    packets: list[dict] = field(
        default_factory=list
    )

    statistics: dict = field(
        default_factory=dict
    )

    alerts: list[Alert] = field(
        default_factory=list
    )

    risk_score: int = 0
    risk_level: str = "LOW"

    risk_breakdown: list[dict] = field(
        default_factory=list
    )

    analysis_duration: float = 0.0