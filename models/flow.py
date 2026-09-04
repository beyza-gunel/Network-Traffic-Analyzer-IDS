from dataclasses import dataclass, field


@dataclass
class FlowRecord:
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None

    first_seen: float
    last_seen: float

    packet_count: int = 0
    byte_count: int = 0

    forward_packets: int = 0
    reverse_packets: int = 0

    application_protocol: str | None = None

    tcp_flags: list[str] = field(
        default_factory=list
    )

    @property
    def duration(self) -> float:
        return max(
            0.0,
            float(self.last_seen)
            - float(self.first_seen),
        )

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "application_protocol": self.application_protocol,
            "tcp_flags": list(
                self.tcp_flags
            ),
        }
