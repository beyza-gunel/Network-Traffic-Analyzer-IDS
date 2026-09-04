from dataclasses import dataclass, field
from typing import Any

from models.alert import Alert
from models.flow import FlowRecord


@dataclass
class AnalysisResult:
    file_path: str
    file_name: str

    total_packets: int
    total_bytes: int

    packets: list[dict[str, Any]] = field(
        default_factory=list
    )

    statistics: dict[str, Any] = field(
        default_factory=dict
    )

    alerts: list[Alert] = field(
        default_factory=list
    )

    flows: list[FlowRecord] = field(
        default_factory=list
    )

    risk_score: int = 0
    risk_level: str = "LOW"

    risk_breakdown: list[dict[str, Any]] = field(
        default_factory=list
    )

    analysis_duration: float = 0.0
