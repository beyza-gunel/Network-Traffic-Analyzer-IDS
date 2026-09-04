import html
import json
import textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path

from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure


MAX_REPORT_PACKETS = 5000
TOP_ITEMS = 20


def _alert_level(alert):
    severity = str(alert.get("severity") or "").upper()

    if severity in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        return severity

    score = int(
        alert.get(
            "risk_score",
            0,
        )
        or 0
    )

    if score >= 12:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


def _json_safe(value):
    if value is None:
        return None

    if isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return [
            _json_safe(item)
            for item in value
        ]

    return str(value)


def build_report_data(
    file_path,
    packets,
    statistics,
    alerts,
    risk_score,
    risk_level,
    risk_breakdown=None,
):
    protocol_counter = Counter()
    ip_counter = Counter()
    connection_counter = Counter()

    first_timestamp = None
    last_timestamp = None

    for packet in packets:
        protocol = packet.get(
            "protocol"
        )

        if protocol:
            protocol_counter[
                protocol
            ] += 1

        src_ip = packet.get(
            "src_ip"
        )
        dst_ip = packet.get(
            "dst_ip"
        )

        if src_ip:
            ip_counter[
                src_ip
            ] += 1

        if dst_ip:
            ip_counter[
                dst_ip
            ] += 1

        if (
            src_ip
            and dst_ip
            and src_ip != dst_ip
        ):
            connection_counter[
                (
                    src_ip,
                    dst_ip,
                )
            ] += 1

        timestamp = packet.get(
            "timestamp"
        )

        if timestamp is not None:
            timestamp = float(
                timestamp
            )

            if (
                first_timestamp is None
                or timestamp
                < first_timestamp
            ):
                first_timestamp = (
                    timestamp
                )

            if (
                last_timestamp is None
                or timestamp
                > last_timestamp
            ):
                last_timestamp = (
                    timestamp
                )

    alert_type_counter = Counter(
        alert.get(
            "type",
            "UNKNOWN",
        )
        for alert in alerts
    )

    alert_level_counter = Counter(
        _alert_level(alert)
        for alert in alerts
    )

    packet_sample = [
        _json_safe(packet)
        for packet in packets[
            :MAX_REPORT_PACKETS
        ]
    ]

    report = {
        "generated_at": (
            datetime.now().isoformat(
                timespec="seconds"
            )
        ),
        "pcap_file": str(
            file_path or ""
        ),
        "pcap_file_name": (
            Path(file_path).name
            if file_path
            else ""
        ),
        "analysis_period": {
            "first_timestamp": (
                first_timestamp
            ),
            "last_timestamp": (
                last_timestamp
            ),
        },
        "statistics": _json_safe(
            statistics
        ),
        "risk": {
            "score": int(
                risk_score or 0
            ),
            "level": str(
                risk_level or "LOW"
            ),
            "breakdown": _json_safe(
                risk_breakdown or []
            ),
        },
        "alerts": [
            {
                **_json_safe(
                    alert
                ),
                "derived_level": (
                    _alert_level(
                        alert
                    )
                ),
            }
            for alert in alerts
        ],
        "summary": {
            "protocol_distribution": (
                dict(
                    protocol_counter
                )
            ),
            "alert_type_distribution": (
                dict(
                    alert_type_counter
                )
            ),
            "alert_level_distribution": (
                dict(
                    alert_level_counter
                )
            ),
            "top_ips": [
                {
                    "ip": ip,
                    "packet_references": count,
                }
                for ip, count
                in ip_counter.most_common(
                    TOP_ITEMS
                )
            ],
            "top_connections": [
                {
                    "source_ip": source,
                    "destination_ip": destination,
                    "packets": count,
                }
                for (
                    source,
                    destination,
                ), count
                in connection_counter.most_common(
                    TOP_ITEMS
                )
            ],
        },
        "packet_sample": packet_sample,
        "packet_sample_limit": (
            MAX_REPORT_PACKETS
        ),
        "packet_sample_truncated": (
            len(packets)
            > MAX_REPORT_PACKETS
        ),
    }

    return report


def export_json(
    output_path,
    report_data,
):
    path = Path(
        output_path
    )

    path.write_text(
        json.dumps(
            report_data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path


def export_html(
    output_path,
    report_data,
):
    path = Path(
        output_path
    )

    stats = report_data.get(
        "statistics",
        {},
    )

    alerts = report_data.get(
        "alerts",
        [],
    )

    risk = report_data.get(
        "risk",
        {},
    )

    protocol_distribution = (
        report_data
        .get(
            "summary",
            {},
        )
        .get(
            "protocol_distribution",
            {},
        )
    )

    alert_rows = []

    for alert in alerts:
        evidence = "<br>".join(
            html.escape(
                str(item)
            )
            for item in (
                alert.get(
                    "evidence"
                )
                or []
            )
        )

        alert_rows.append(
            f"""
            <tr>
                <td>{html.escape(str(alert.get("type", "")))}</td>
                <td>{html.escape(str(alert.get("derived_level", "")))}</td>
                <td>{html.escape(str(alert.get("risk_score", "")))}</td>
                <td>{html.escape(str(alert.get("source_ip") or ""))}</td>
                <td>{html.escape(str(alert.get("destination_ip") or ""))}</td>
                <td>{html.escape(str(alert.get("reason") or ""))}</td>
                <td>{evidence}</td>
            </tr>
            """
        )

    protocol_rows = "".join(
        (
            "<tr>"
            f"<td>{html.escape(str(protocol))}</td>"
            f"<td>{count}</td>"
            "</tr>"
        )
        for protocol, count
        in sorted(
            protocol_distribution.items()
        )
    )

    document = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Network Traffic Analyzer IDS Report</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        margin: 32px;
        background: #f7f7f7;
        color: #171717;
    }}
    .container {{
        max-width: 1200px;
        margin: auto;
        background: white;
        padding: 28px;
        border-radius: 10px;
    }}
    h1, h2 {{
        margin-top: 0;
    }}
    .cards {{
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin: 20px 0;
    }}
    .card {{
        border: 1px solid #d7d7d7;
        padding: 14px;
        border-radius: 8px;
    }}
    .value {{
        font-size: 24px;
        font-weight: bold;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 24px;
    }}
    th, td {{
        border: 1px solid #d7d7d7;
        padding: 8px;
        text-align: left;
        vertical-align: top;
    }}
    th {{
        background: #eeeeee;
    }}
    .note {{
        color: #555;
        font-size: 13px;
    }}
</style>
</head>
<body>
<div class="container">
    <h1>Network Traffic Analyzer & IDS Report</h1>
    <p><b>PCAP:</b> {html.escape(str(report_data.get("pcap_file_name", "")))}</p>
    <p><b>Generated:</b> {html.escape(str(report_data.get("generated_at", "")))}</p>

    <div class="cards">
        <div class="card">
            <div>Total Packets</div>
            <div class="value">{stats.get("total_packets", 0)}</div>
        </div>
        <div class="card">
            <div>Unique IPs</div>
            <div class="value">{stats.get("unique_ips", 0)}</div>
        </div>
        <div class="card">
            <div>Unique Ports</div>
            <div class="value">{stats.get("unique_ports", 0)}</div>
        </div>
        <div class="card">
            <div>TCP Connections</div>
            <div class="value">{stats.get("tcp_connections", 0)}</div>
        </div>
        <div class="card">
            <div>Alerts</div>
            <div class="value">{len(alerts)}</div>
        </div>
        <div class="card">
            <div>Risk Score</div>
            <div class="value">{risk.get("score", 0)}</div>
        </div>
        <div class="card">
            <div>Risk Level</div>
            <div class="value">{html.escape(str(risk.get("level", "LOW")))}</div>
        </div>
        <div class="card">
            <div>UDP Traffic</div>
            <div class="value">{stats.get("udp_packets", 0)}</div>
        </div>
    </div>

    <h2>Protocol Distribution</h2>
    <table>
        <thead>
            <tr>
                <th>Protocol</th>
                <th>Packets</th>
            </tr>
        </thead>
        <tbody>
            {protocol_rows}
        </tbody>
    </table>

    <h2>Security Alerts</h2>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Level</th>
                <th>Risk</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Reason</th>
                <th>Evidence</th>
            </tr>
        </thead>
        <tbody>
            {''.join(alert_rows)}
        </tbody>
    </table>

    <p class="note">
        JSON report contains up to
        {report_data.get("packet_sample_limit", MAX_REPORT_PACKETS)}
        parsed packet samples to prevent extremely large report files.
    </p>
</div>
</body>
</html>
"""

    path.write_text(
        document,
        encoding="utf-8",
    )

    return path


def _add_pdf_text_page(
    pdf,
    title,
    lines,
):
    figure = Figure(
        figsize=(8.27, 11.69)
    )

    axis = figure.add_subplot(
        111
    )

    axis.axis(
        "off"
    )

    axis.text(
        0.04,
        0.97,
        title,
        fontsize=16,
        fontweight="bold",
        va="top",
    )

    y = 0.925

    for line in lines:
        wrapped_lines = (
            textwrap.wrap(
                str(line),
                width=100,
            )
            or [""]
        )

        for wrapped in wrapped_lines:
            if y < 0.05:
                pdf.savefig(
                    figure,
                    bbox_inches="tight",
                )

                figure = Figure(
                    figsize=(8.27, 11.69)
                )
                axis = (
                    figure
                    .add_subplot(
                        111
                    )
                )
                axis.axis(
                    "off"
                )
                axis.text(
                    0.04,
                    0.97,
                    title,
                    fontsize=16,
                    fontweight="bold",
                    va="top",
                )
                y = 0.925

            axis.text(
                0.04,
                y,
                wrapped,
                fontsize=9,
                va="top",
            )

            y -= 0.027

    pdf.savefig(
        figure,
        bbox_inches="tight",
    )


def export_pdf(
    output_path,
    report_data,
):
    path = Path(
        output_path
    )

    stats = report_data.get(
        "statistics",
        {},
    )
    risk = report_data.get(
        "risk",
        {},
    )
    alerts = report_data.get(
        "alerts",
        [],
    )

    with PdfPages(path) as pdf:
        summary_lines = [
            (
                "PCAP: "
                f"{report_data.get('pcap_file_name', '')}"
            ),
            (
                "Generated: "
                f"{report_data.get('generated_at', '')}"
            ),
            "",
            (
                "Total Packets: "
                f"{stats.get('total_packets', 0)}"
            ),
            (
                "Unique IPs: "
                f"{stats.get('unique_ips', 0)}"
            ),
            (
                "Unique Ports: "
                f"{stats.get('unique_ports', 0)}"
            ),
            (
                "TCP Connections: "
                f"{stats.get('tcp_connections', 0)}"
            ),
            (
                "UDP Traffic: "
                f"{stats.get('udp_packets', 0)}"
            ),
            (
                "Alert Count: "
                f"{len(alerts)}"
            ),
            (
                "Risk Score: "
                f"{risk.get('score', 0)}"
            ),
            (
                "Risk Level: "
                f"{risk.get('level', 'LOW')}"
            ),
            "",
            "Protocol Distribution:",
        ]

        for protocol, count in (
            report_data
            .get(
                "summary",
                {},
            )
            .get(
                "protocol_distribution",
                {},
            )
            .items()
        ):
            summary_lines.append(
                f"  {protocol}: {count}"
            )

        _add_pdf_text_page(
            pdf,
            "Network Traffic Analyzer & IDS Report",
            summary_lines,
        )

        alert_lines = []

        if not alerts:
            alert_lines.append(
                "No security alerts were detected."
            )

        for index, alert in enumerate(
            alerts,
            start=1,
        ):
            alert_lines.extend(
                [
                    (
                        f"{index}. "
                        f"{alert.get('type', 'UNKNOWN')} "
                        f"[{alert.get('derived_level', '')}] "
                        f"Risk={alert.get('risk_score', 0)}"
                    ),
                    (
                        "Source: "
                        f"{alert.get('source_ip') or '-'} "
                        "Destination: "
                        f"{alert.get('destination_ip') or '-'}"
                    ),
                    (
                        "Reason: "
                        f"{alert.get('reason') or '-'}"
                    ),
                    "Evidence:",
                ]
            )

            evidence = (
                alert.get(
                    "evidence"
                )
                or []
            )

            if evidence:
                for item in evidence:
                    alert_lines.append(
                        f"  - {item}"
                    )
            else:
                alert_lines.append(
                    "  - No additional evidence."
                )

            alert_lines.append(
                ""
            )

        _add_pdf_text_page(
            pdf,
            "Security Alerts",
            alert_lines,
        )

    return path
