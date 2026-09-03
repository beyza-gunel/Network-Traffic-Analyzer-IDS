from dataclasses import dataclass, field


@dataclass
class Alert:
    alert_type: str
    severity: str
    risk_score: int
    confidence: float
    reason: str

    source_ip: str | None = None
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    first_seen: float | None = None
    last_seen: float | None = None

    packet_count: int = 0

    evidence: list[str] = field(default_factory=list)