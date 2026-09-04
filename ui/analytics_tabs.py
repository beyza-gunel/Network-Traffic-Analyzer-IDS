from collections import Counter, defaultdict
from datetime import datetime

import networkx as nx

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QFrame,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QSplitter,
)

from matplotlib.backends.backend_qtagg import (
    FigureCanvasQTAgg as FigureCanvas,
)
from matplotlib.figure import Figure
from matplotlib.patches import Patch
import matplotlib.dates as mdates


BG = "#08111f"
PANEL = "#0d192b"
AXIS = "#0b1727"
TEXT = "#dce7f4"
MUTED = "#8295ad"
GRID = "#26384f"
PRIMARY = "#38bdf8"
DANGER = "#f87171"
SUCCESS = "#4ade80"


def _configure_axis(
    figure,
    axis,
    title,
):
    figure.set_facecolor(
        PANEL
    )

    axis.set_facecolor(
        AXIS
    )

    axis.set_title(
        title,
        color=TEXT,
        fontsize=13,
        fontweight="bold",
        pad=12,
    )

    axis.tick_params(
        colors=MUTED
    )

    axis.xaxis.label.set_color(
        MUTED
    )
    axis.yaxis.label.set_color(
        MUTED
    )

    for spine in (
        axis.spines.values()
    ):
        spine.set_color(
            GRID
        )


def _section_header(
    title,
    subtitle,
):
    frame = QFrame()
    frame.setObjectName(
        "detailPanel"
    )

    layout = QVBoxLayout(
        frame
    )
    layout.setContentsMargins(
        14,
        10,
        14,
        10,
    )
    layout.setSpacing(
        2
    )

    title_label = QLabel(
        title
    )
    title_label.setObjectName(
        "sectionTitle"
    )

    subtitle_label = QLabel(
        subtitle
    )
    subtitle_label.setObjectName(
        "sectionSubtitle"
    )

    layout.addWidget(
        title_label
    )
    layout.addWidget(
        subtitle_label
    )

    return frame


def _format_timestamp(
    timestamp,
):
    if timestamp is None:
        return "-"

    try:
        return datetime.fromtimestamp(
            float(
                timestamp
            )
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        TypeError,
        ValueError,
        OverflowError,
        OSError,
    ):
        return str(
            timestamp
        )


def _alert_source_entity(
    alert,
):
    source_ip = alert.get(
        "source_ip"
    )

    if source_ip:
        return str(
            source_ip
        )

    evidence = (
        alert.get(
            "evidence"
        )
        or []
    )

    prefixes = (
        "Source MAC:",
        "MAC 1:",
        "AP MAC:",
        "Attacker MAC:",
        "BSSID:",
    )

    for prefix in prefixes:
        for item in evidence:
            value = str(
                item
            )

            if value.lower().startswith(
                prefix.lower()
            ):
                return (
                    value.split(
                        ":",
                        1,
                    )[1]
                    .strip()
                )

    return "-"



class TimelineTab(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(
            self
        )
        layout.setContentsMargins(
            10,
            10,
            10,
            10,
        )
        layout.setSpacing(
            8
        )

        layout.addWidget(
            _section_header(
                "Attack & Traffic Timeline",
                (
                    "Paket yoğunluğu solda, tespit edilen güvenlik "
                    "olayları sağda zaman sırasıyla gösterilir."
                ),
            )
        )

        # Dikey yerleşimde grafik ve tablo birbirini fazla sıkıştırıyordu.
        # Geniş masaüstü ekranını daha iyi kullanmak için yatay splitter.
        self.timeline_splitter = QSplitter(
            Qt.Horizontal
        )

        # ------------------------------------------------------
        # SOL: TRAFFIC + EVENT MARKERS
        # ------------------------------------------------------
        chart_panel = QFrame()
        chart_panel.setObjectName(
            "detailPanel"
        )

        chart_layout = QVBoxLayout(
            chart_panel
        )
        chart_layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        chart_layout.setSpacing(
            4
        )

        self.figure = Figure(
            figsize=(8, 5),
            facecolor=PANEL,
        )

        self.canvas = FigureCanvas(
            self.figure
        )
        self.canvas.setMinimumHeight(
            300
        )

        chart_layout.addWidget(
            self.canvas,
            1,
        )

        self.timeline_splitter.addWidget(
            chart_panel
        )

        # ------------------------------------------------------
        # SAĞ: EVENT LIST + DETAIL
        # ------------------------------------------------------
        event_panel = QFrame()
        event_panel.setObjectName(
            "detailPanel"
        )

        event_layout = QVBoxLayout(
            event_panel
        )
        event_layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        event_layout.setSpacing(
            6
        )

        event_title = QLabel(
            "Detected Security Events"
        )
        event_title.setObjectName(
            "sectionTitle"
        )
        event_layout.addWidget(
            event_title
        )

        self.event_table = QTableWidget()

        columns = [
            "Time",
            "Alert Type",
            "Source",
            "Risk",
        ]

        self.event_table.setColumnCount(
            len(
                columns
            )
        )

        self.event_table.setHorizontalHeaderLabels(
            columns
        )

        header = self.event_table.horizontalHeader()
        header.setSectionResizeMode(
            0,
            QHeaderView.ResizeToContents,
        )
        header.setSectionResizeMode(
            1,
            QHeaderView.Stretch,
        )
        header.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )
        header.setSectionResizeMode(
            3,
            QHeaderView.ResizeToContents,
        )

        self.event_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.event_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.event_table.setSelectionMode(
            QTableWidget.SingleSelection
        )
        self.event_table.setAlternatingRowColors(
            True
        )
        self.event_table.verticalHeader().setDefaultSectionSize(
            30
        )
        self.event_table.setMinimumHeight(
            120
        )

        self.event_detail = QTextEdit()
        self.event_detail.setReadOnly(
            True
        )
        self.event_detail.setMinimumHeight(
            80
        )
        self.event_detail.setPlaceholderText(
            "Bir güvenlik olayını seçerek reason ve evidence detaylarını görüntüleyin."
        )

        self.event_content_splitter = QSplitter(
            Qt.Vertical
        )

        self.event_content_splitter.addWidget(
            self.event_table
        )

        self.event_content_splitter.addWidget(
            self.event_detail
        )

        self.event_content_splitter.setStretchFactor(
            0,
            3
        )

        self.event_content_splitter.setStretchFactor(
            1,
            2
        )

        self.event_content_splitter.setSizes(
            [
                190,
                120,
            ]
        )

        self.event_content_splitter.setChildrenCollapsible(
            False
        )

        event_layout.addWidget(
            self.event_content_splitter,
            1,
        )

        self.timeline_splitter.addWidget(
            event_panel
        )

        self.timeline_splitter.setStretchFactor(
            0,
            5
        )
        self.timeline_splitter.setStretchFactor(
            1,
            4
        )
        self.timeline_splitter.setSizes(
            [
                720,
                560,
            ]
        )
        self.timeline_splitter.setChildrenCollapsible(
            False
        )

        layout.addWidget(
            self.timeline_splitter,
            1,
        )

        self.timeline_alerts = []

        self.event_table.cellClicked.connect(
            self.show_event_detail
        )

    @staticmethod
    def _resolve_alert_timestamp(
        alert,
        packets,
    ):
        """Alarmda first_seen yoksa ilgili IP/MAC paketlerinden zaman üret."""
        first_seen = alert.get(
            "first_seen"
        )

        if first_seen is not None:
            try:
                return float(
                    first_seen
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        source_ip = alert.get(
            "source_ip"
        )
        destination_ip = alert.get(
            "destination_ip"
        )

        evidence_text = " ".join(
            str(
                item
            ).lower()
            for item
            in (
                alert.get(
                    "evidence"
                )
                or []
            )
        )

        candidates = []

        for packet in packets:
            matched = False

            if source_ip and (
                packet.get(
                    "src_ip"
                ) == source_ip
            ):
                matched = True

            elif destination_ip and (
                packet.get(
                    "dst_ip"
                ) == destination_ip
            ):
                matched = True

            elif evidence_text:
                for key in (
                    "src_mac",
                    "dst_mac",
                    "bssid",
                    "wlan_addr1",
                    "wlan_addr2",
                    "wlan_addr3",
                ):
                    value = packet.get(
                        key
                    )

                    if (
                        value
                        and str(
                            value
                        ).lower()
                        in evidence_text
                    ):
                        matched = True
                        break

            if not matched:
                continue

            timestamp = packet.get(
                "timestamp"
            )

            if timestamp is None:
                continue

            try:
                candidates.append(
                    float(
                        timestamp
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

        if candidates:
            return min(
                candidates
            )

        return None

    def update_data(
        self,
        packets,
        alerts,
    ):
        self.figure.clear()

        axis = self.figure.add_subplot(
            111
        )

        _configure_axis(
            self.figure,
            axis,
            "Traffic Volume + Security Events",
        )

        traffic_per_second = Counter()

        for packet in packets:
            timestamp = packet.get(
                "timestamp"
            )

            if timestamp is None:
                continue

            try:
                second = int(
                    float(
                        timestamp
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

            traffic_per_second[
                second
            ] += 1

        seconds = sorted(
            traffic_per_second
        )

        if seconds:
            values = [
                traffic_per_second[
                    second
                ]
                for second
                in seconds
            ]

            times = [
                datetime.fromtimestamp(
                    second
                )
                for second
                in seconds
            ]

            axis.plot(
                times,
                values,
                linewidth=2.0,
                color=PRIMARY,
                marker="o",
                markersize=3.5,
                label="Traffic",
            )

            axis.fill_between(
                times,
                values,
                alpha=0.10,
                color=PRIMARY,
            )

            # Küçük sentetik PCAP'lerde çizginin üst/alt kenara yapışmasını önle.
            maximum_value = max(
                values
            )

            axis.set_ylim(
                bottom=0,
                top=max(
                    1,
                    maximum_value
                    * 1.25,
                ),
            )

        else:
            axis.text(
                0.5,
                0.5,
                "Zaman bilgisi bulunan paket yok.",
                color=MUTED,
                ha="center",
                va="center",
            )

        timeline_alerts = []

        for alert in alerts:
            resolved_time = self._resolve_alert_timestamp(
                alert,
                packets,
            )

            copied_alert = dict(
                alert
            )
            copied_alert[
                "_timeline_time"
            ] = resolved_time

            timeline_alerts.append(
                copied_alert
            )

        timeline_alerts.sort(
            key=lambda alert: (
                alert.get(
                    "_timeline_time"
                )
                if alert.get(
                    "_timeline_time"
                )
                is not None
                else float(
                    "inf"
                )
            )
        )

        for alert in timeline_alerts[
            :30
        ]:
            event_timestamp = alert.get(
                "_timeline_time"
            )

            if event_timestamp is None:
                continue

            try:
                alert_time = datetime.fromtimestamp(
                    float(
                        event_timestamp
                    )
                )

                axis.axvline(
                    alert_time,
                    linestyle="--",
                    alpha=0.72,
                    linewidth=1.25,
                    color=DANGER,
                )

            except Exception:
                pass

        axis.set_xlabel(
            "Time"
        )
        axis.set_ylabel(
            "Packets / Second"
        )
        axis.grid(
            True,
            alpha=0.25,
            color=GRID,
        )

        # Zaman etiketlerini kısa ve okunabilir tut.
        # Tam tarih olay tablosunda zaten gösterildiği için grafikte
        # yalnız saat:dakika:saniye kullanılır.
        axis.xaxis.set_major_formatter(
            mdates.DateFormatter(
                "%H:%M:%S"
            )
        )

        for tick_label in axis.get_xticklabels():
            tick_label.set_rotation(
                18
            )
            tick_label.set_horizontalalignment(
                "right"
            )

        # Alt etiketlerin panel sınırında kesilmesini önle.
        self.figure.subplots_adjust(
            left=0.11,
            right=0.98,
            top=0.88,
            bottom=0.22,
        )

        self.canvas.draw()

        self.timeline_alerts = timeline_alerts

        self.event_table.setRowCount(
            len(
                timeline_alerts
            )
        )

        for row, alert in enumerate(
            timeline_alerts
        ):
            values = [
                _format_timestamp(
                    alert.get(
                        "_timeline_time"
                    )
                ),
                alert.get(
                    "type",
                    "UNKNOWN",
                ),
                _alert_source_entity(
                    alert
                ),
                alert.get(
                    "risk_score",
                    0,
                ),
            ]

            for column, value in enumerate(
                values
            ):
                item = QTableWidgetItem(
                    str(
                        value
                    )
                )

                if (
                    column == 3
                    and int(
                        alert.get(
                            "risk_score",
                            0,
                        )
                        or 0
                    )
                    >= 10
                ):
                    item.setForeground(
                        QColor(
                            DANGER
                        )
                    )

                self.event_table.setItem(
                    row,
                    column,
                    item,
                )

        self.event_detail.clear()

        if timeline_alerts:
            self.event_table.selectRow(
                0
            )
            self.show_event_detail(
                0,
                0,
            )

    def show_event_detail(
        self,
        row,
        column,
    ):
        if (
            row < 0
            or row >= len(
                self.timeline_alerts
            )
        ):
            return

        alert = self.timeline_alerts[
            row
        ]

        evidence = alert.get(
            "evidence"
        ) or []

        evidence_text = "\n".join(
            f"- {item}"
            for item
            in evidence
        )

        if not evidence_text:
            evidence_text = "- Evidence bilgisi yok."

        detail = (
            f"Time: {_format_timestamp(alert.get('_timeline_time'))}\n"
            f"Alert: {alert.get('type', 'UNKNOWN')}\n"
            f"Source: {_alert_source_entity(alert)}\n"
            f"Risk: {alert.get('risk_score', 0)}\n"
            f"Reason: {alert.get('reason', '')}\n\n"
            f"Evidence:\n{evidence_text}"
        )

        self.event_detail.setPlainText(
            detail
        )


class IPAnalysisTab(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(
            self
        )
        layout.setContentsMargins(
            12,
            12,
            12,
            12,
        )
        layout.setSpacing(
            10
        )

        layout.addWidget(
            _section_header(
                "IP Analysis",
                (
                    "Her IP için paket sayısı, protokoller, portlar, "
                    "zaman aralığı, bağlantılar ve risk ilişkisini gösterir."
                ),
            )
        )

        self.table = QTableWidget()

        columns = [
            "IP Address",
            "Packet Count",
            "Protocols",
            "Ports",
            "First Seen",
            "Last Seen",
            "Connections",
            "Risk Score",
            "Alerts",
            "Status",
        ]

        self.table.setColumnCount(
            len(
                columns
            )
        )

        self.table.setHorizontalHeaderLabels(
            columns
        )

        header = self.table.horizontalHeader()

        header.setStretchLastSection(
            False
        )

        # IP Analysis ekranındaki kritik sütunları pencere içinde
        # görünür tut. Ports sütunu kalan alanı esnek olarak kullanır.
        fixed_widths = {
            0: 115,   # IP Address
            1: 100,   # Packet Count
            2: 95,    # Protocols
            4: 160,   # First Seen
            5: 160,   # Last Seen
            6: 100,   # Connections
            7: 90,    # Risk Score
            8: 70,    # Alerts
            9: 115,   # Status
        }

        for column, width in fixed_widths.items():
            header.setSectionResizeMode(
                column,
                QHeaderView.Fixed,
            )

            self.table.setColumnWidth(
                column,
                width,
            )

        header.setSectionResizeMode(
            3,
            QHeaderView.Stretch,
        )

        # Tam ekran kullanımında sağ tarafta boş alan bırakma.
        # Ports ve Status kalan genişliği birlikte kullanır.
        header.setSectionResizeMode(
            9,
            QHeaderView.Stretch,
        )

        self.table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.table.setAlternatingRowColors(
            True
        )

        self.detail_splitter = QSplitter(
            Qt.Vertical
        )

        self.detail_splitter.addWidget(
            self.table
        )

        self.detail = QTextEdit()

        self.detail.setReadOnly(
            True
        )

        self.detail.setPlaceholderText(
            (
                "Bir IP adresine tıklayarak güvenlik "
                "analiz detayını ve neden şüpheli olduğunu görüntüleyin."
            )
        )

        self.detail_splitter.addWidget(
            self.detail
        )

        self.detail_splitter.setStretchFactor(
            0,
            3
        )

        self.detail_splitter.setStretchFactor(
            1,
            2
        )

        self.detail_splitter.setSizes(
            [
                470,
                190,
            ]
        )

        layout.addWidget(
            self.detail_splitter,
            1,
        )

        self.ip_details = {}

        self.table.cellClicked.connect(
            self.show_ip_detail
        )

    def update_data(
        self,
        packets,
        alerts,
    ):
        ip_stats = defaultdict(
            lambda: {
                "sent": 0,
                "received": 0,
                "protocols": set(),
                "ports": set(),
                "connections": set(),
                "first_seen": None,
                "last_seen": None,
                "alerts": [],
            }
        )

        def register_timestamp(
            info,
            timestamp,
        ):
            if timestamp is None:
                return

            try:
                timestamp = float(
                    timestamp
                )

            except (
                TypeError,
                ValueError,
            ):
                return

            if (
                info[
                    "first_seen"
                ]
                is None
                or timestamp
                < info[
                    "first_seen"
                ]
            ):
                info[
                    "first_seen"
                ] = timestamp

            if (
                info[
                    "last_seen"
                ]
                is None
                or timestamp
                > info[
                    "last_seen"
                ]
            ):
                info[
                    "last_seen"
                ] = timestamp

        for packet in packets:
            src_ip = packet.get(
                "src_ip"
            )

            dst_ip = packet.get(
                "dst_ip"
            )

            protocol = packet.get(
                "protocol"
            )

            src_port = packet.get(
                "src_port"
            )

            dst_port = packet.get(
                "dst_port"
            )

            timestamp = packet.get(
                "timestamp"
            )

            if src_ip:
                source_info = ip_stats[
                    src_ip
                ]

                source_info[
                    "sent"
                ] += 1

                if protocol:
                    source_info[
                        "protocols"
                    ].add(
                        protocol
                    )

                if (
                    src_port
                    is not None
                ):
                    source_info[
                        "ports"
                    ].add(
                        src_port
                    )

                if (
                    dst_port
                    is not None
                ):
                    source_info[
                        "ports"
                    ].add(
                        dst_port
                    )

                if (
                    dst_ip
                    and dst_ip
                    != src_ip
                ):
                    source_info[
                        "connections"
                    ].add(
                        dst_ip
                    )

                register_timestamp(
                    source_info,
                    timestamp,
                )

            if dst_ip:
                destination_info = (
                    ip_stats[
                        dst_ip
                    ]
                )

                destination_info[
                    "received"
                ] += 1

                if protocol:
                    destination_info[
                        "protocols"
                    ].add(
                        protocol
                    )

                if (
                    src_port
                    is not None
                ):
                    destination_info[
                        "ports"
                    ].add(
                        src_port
                    )

                if (
                    dst_port
                    is not None
                ):
                    destination_info[
                        "ports"
                    ].add(
                        dst_port
                    )

                if (
                    src_ip
                    and src_ip
                    != dst_ip
                ):
                    destination_info[
                        "connections"
                    ].add(
                        src_ip
                    )

                register_timestamp(
                    destination_info,
                    timestamp,
                )

        for alert in alerts:
            source_ip = alert.get(
                "source_ip"
            )

            destination_ip = (
                alert.get(
                    "destination_ip"
                )
            )

            if source_ip:
                ip_stats[
                    source_ip
                ][
                    "alerts"
                ].append(
                    alert
                )

            if (
                destination_ip
                and destination_ip
                != source_ip
            ):
                ip_stats[
                    destination_ip
                ][
                    "alerts"
                ].append(
                    alert
                )

        ordered_ips = sorted(
            ip_stats.items(),
            key=lambda item: (
                item[1][
                    "sent"
                ]
                + item[1][
                    "received"
                ]
            ),
            reverse=True,
        )

        self.table.setRowCount(
            len(
                ordered_ips
            )
        )

        self.ip_details = {}

        for (
            row,
            (
                ip_address,
                info,
            ),
        ) in enumerate(
            ordered_ips
        ):
            packet_count = (
                info[
                    "sent"
                ]
                + info[
                    "received"
                ]
            )

            alert_count = len(
                info[
                    "alerts"
                ]
            )

            risk_score = max(
                (
                    int(
                        alert.get(
                            "risk_score",
                            0,
                        )
                        or 0
                    )
                    for alert
                    in info[
                        "alerts"
                    ]
                ),
                default=0,
            )

            status = (
                "SUSPICIOUS"
                if alert_count
                > 0
                else "NORMAL"
            )

            protocols = ", ".join(
                sorted(
                    str(
                        protocol
                    )
                    for protocol
                    in info[
                        "protocols"
                    ]
                )
            )

            sorted_ports = sorted(
                info[
                    "ports"
                ]
            )

            if len(
                sorted_ports
            ) <= 8:
                ports_text = ", ".join(
                    str(
                        port
                    )
                    for port
                    in sorted_ports
                )
            else:
                ports_text = (
                    ", ".join(
                        str(
                            port
                        )
                        for port
                        in sorted_ports[
                            :8
                        ]
                    )
                    + f" (+{len(sorted_ports) - 8})"
                )

            values = [
                ip_address,
                packet_count,
                protocols,
                ports_text,
                _format_timestamp(
                    info[
                        "first_seen"
                    ]
                ),
                _format_timestamp(
                    info[
                        "last_seen"
                    ]
                ),
                len(
                    info[
                        "connections"
                    ]
                ),
                risk_score,
                alert_count,
                status,
            ]

            for (
                column,
                value,
            ) in enumerate(
                values
            ):
                item = QTableWidgetItem(
                    str(
                        value
                    )
                )

                if (
                    column == 9
                    and status
                    == "SUSPICIOUS"
                ):
                    item.setForeground(
                        QColor(
                            DANGER
                        )
                    )

                if (
                    column == 7
                    and risk_score
                    >= 10
                ):
                    item.setForeground(
                        QColor(
                            DANGER
                        )
                    )

                self.table.setItem(
                    row,
                    column,
                    item,
                )

            self.ip_details[
                ip_address
            ] = info

    def show_ip_detail(
        self,
        row,
        column,
    ):
        item = self.table.item(
            row,
            0,
        )

        if item is None:
            return

        ip_address = item.text()

        info = self.ip_details.get(
            ip_address
        )

        if not info:
            return

        packet_count = (
            info[
                "sent"
            ]
            + info[
                "received"
            ]
        )

        risk_score = max(
            (
                int(
                    alert.get(
                        "risk_score",
                        0,
                    )
                    or 0
                )
                for alert
                in info[
                    "alerts"
                ]
            ),
            default=0,
        )

        alert_lines = []

        for alert in info[
            "alerts"
        ]:
            alert_lines.append(
                (
                    f"- {alert.get('type')} | "
                    f"Risk: {alert.get('risk_score')} | "
                    f"{alert.get('reason')}"
                )
            )

        if not alert_lines:
            alert_lines.append(
                (
                    "- Bu IP ile ilişkilendirilmiş "
                    "güvenlik alarmı yok."
                )
            )

        connections_text = ", ".join(
            sorted(
                str(
                    connection
                )
                for connection
                in info[
                    "connections"
                ]
            )
        )

        if not connections_text:
            connections_text = "-"

        ports_text = ", ".join(
            str(
                port
            )
            for port
            in sorted(
                info[
                    "ports"
                ]
            )
        )

        if not ports_text:
            ports_text = "-"

        text = (
            f"IP Address: {ip_address}\n"
            f"Packet Count: {packet_count}\n"
            f"Sent Packets: {info['sent']}\n"
            f"Received Packets: {info['received']}\n"
            f"Protocols: "
            f"{', '.join(sorted(str(p) for p in info['protocols']))}\n"
            f"Ports: {ports_text}\n"
            f"First Seen: {_format_timestamp(info['first_seen'])}\n"
            f"Last Seen: {_format_timestamp(info['last_seen'])}\n"
            f"Connections: {len(info['connections'])}\n"
            f"Connected IPs: {connections_text}\n"
            f"Risk Score: {risk_score}\n"
            f"Alert Count: {len(info['alerts'])}\n\n"
            f"Why Suspicious?\n"
            + "\n".join(
                alert_lines
            )
        )

        self.detail.setPlainText(
            text
        )


class NetworkGraphTab(QWidget):

    MAX_NODES = 40
    MAX_WIRELESS_NODES = 26

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(
            self
        )
        layout.setContentsMargins(
            12,
            12,
            12,
            12,
        )
        layout.setSpacing(
            10
        )

        layout.addWidget(
            _section_header(
                "Network Connection Graph",
                (
                    "IP trafiğinde endpoint bağlantılarını; "
                    "kablosuz trafikte MAC/BSSID ilişkilerini "
                    "ve alarm üreten düğümleri görselleştirir."
                ),
            )
        )

        self.figure = Figure(
            figsize=(8, 6),
            facecolor=PANEL,
        )

        self.canvas = FigureCanvas(
            self.figure
        )

        layout.addWidget(
            self.canvas,
            1,
        )

    @staticmethod
    def _normalize_entity(
        value,
    ):
        if value is None:
            return None

        text = str(
            value
        ).strip()

        if not text:
            return None

        return text.lower()

    def _extract_suspicious_entities(
        self,
        alerts,
    ):
        suspicious = set()

        for alert in alerts:
            for key in (
                "source_ip",
                "destination_ip",
            ):
                value = self._normalize_entity(
                    alert.get(
                        key
                    )
                )

                if value:
                    suspicious.add(
                        value
                    )

            for item in (
                alert.get(
                    "evidence"
                )
                or []
            ):
                text = str(
                    item
                ).strip()

                lowered = text.lower()

                prefixes = (
                    "mac 1:",
                    "mac 2:",
                    "source mac:",
                    "destination mac:",
                    "client mac:",
                    "target mac:",
                    "ap mac:",
                    "attacker mac:",
                    "bssid:",
                )

                for prefix in prefixes:
                    if lowered.startswith(
                        prefix
                    ):
                        value = (
                            text.split(
                                ":",
                                1,
                            )[1]
                            .strip()
                            .lower()
                        )

                        if value:
                            suspicious.add(
                                value
                            )

                        break

        return suspicious

    def _build_ip_graph_data(
        self,
        packets,
    ):
        edge_counter = Counter()
        node_traffic = Counter()

        for packet in packets:
            src_ip = packet.get(
                "src_ip"
            )
            dst_ip = packet.get(
                "dst_ip"
            )

            if (
                not src_ip
                or not dst_ip
                or src_ip == dst_ip
            ):
                continue

            source = str(
                src_ip
            )
            destination = str(
                dst_ip
            )

            edge = tuple(
                sorted(
                    (
                        source,
                        destination,
                    )
                )
            )

            edge_counter[
                edge
            ] += 1

            node_traffic[
                source
            ] += 1
            node_traffic[
                destination
            ] += 1

        return (
            edge_counter,
            node_traffic,
        )

    @staticmethod
    def _is_group_mac(
        mac_address,
    ):
        """
        Broadcast / multicast MAC adreslerini grafik gürültüsünü
        azaltmak için ayıklar. Paket verisi ve detector sonuçları
        değişmez; yalnız görselleştirme sadeleşir.
        """
        if not mac_address:
            return False

        value = str(
            mac_address
        ).strip().lower()

        if value == "ff:ff:ff:ff:ff:ff":
            return True

        try:
            first_octet = int(
                value.split(
                    ":"
                )[0],
                16,
            )

            return bool(
                first_octet
                & 0x01
            )

        except (
            ValueError,
            IndexError,
        ):
            return False

    def _build_wireless_graph_data(
        self,
        packets,
    ):
        edge_counter = Counter()
        node_traffic = Counter()
        bssids = set()

        for packet in packets:
            source = (
                packet.get(
                    "wlan_addr2"
                )
                or packet.get(
                    "src_mac"
                )
            )

            destination = (
                packet.get(
                    "wlan_addr1"
                )
                or packet.get(
                    "dst_mac"
                )
            )

            bssid = packet.get(
                "bssid"
            )

            if bssid:
                bssids.add(
                    str(
                        bssid
                    ).lower()
                )

            if (
                not source
                or not destination
            ):
                continue

            source = str(
                source
            ).lower()

            destination = str(
                destination
            ).lower()

            if source == destination:
                continue

            if (
                self._is_group_mac(
                    source
                )
                or self._is_group_mac(
                    destination
                )
            ):
                continue

            edge = tuple(
                sorted(
                    (
                        source,
                        destination,
                    )
                )
            )

            edge_counter[
                edge
            ] += 1

            node_traffic[
                source
            ] += 1
            node_traffic[
                destination
            ] += 1

        return (
            edge_counter,
            node_traffic,
            bssids,
        )

    def _draw_graph(
        self,
        axis,
        edge_counter,
        node_traffic,
        suspicious_entities,
        title,
        bssids=None,
        max_nodes=None,
    ):
        if not edge_counter:
            axis.text(
                0.5,
                0.5,
                "Bağlantı verisi bulunamadı.",
                color=MUTED,
                ha="center",
                va="center",
            )

            axis.axis(
                "off"
            )

            self.canvas.draw()
            return

        bssids = (
            bssids
            or set()
        )

        node_limit = (
            max_nodes
            if max_nodes is not None
            else self.MAX_NODES
        )

        top_nodes = {
            node
            for (
                node,
                count,
            )
            in node_traffic.most_common(
                node_limit
            )
        }

        graph = nx.Graph()

        for (
            (
                source,
                destination,
            ),
            packet_count,
        ) in edge_counter.items():
            if (
                source
                not in top_nodes
                or destination
                not in top_nodes
            ):
                continue

            graph.add_edge(
                source,
                destination,
                weight=packet_count,
            )

        if graph.number_of_nodes() == 0:
            axis.text(
                0.5,
                0.5,
                "Görselleştirilecek bağlantı bulunamadı.",
                color=MUTED,
                ha="center",
                va="center",
            )

            axis.axis(
                "off"
            )

            self.canvas.draw()
            return

        position = nx.spring_layout(
            graph,
            seed=42,
            k=1.0,
        )

        node_sizes = [
            min(
                520
                + node_traffic[
                    node
                ]
                * 2,
                2800,
            )
            for node
            in graph.nodes
        ]

        bssid_color = "#a78bfa"

        node_colors = []

        for node in graph.nodes:
            normalized = str(
                node
            ).lower()

            if (
                normalized
                in suspicious_entities
            ):
                node_colors.append(
                    DANGER
                )

            elif (
                normalized
                in bssids
            ):
                node_colors.append(
                    bssid_color
                )

            else:
                node_colors.append(
                    PRIMARY
                )

        edge_widths = []

        for (
            source,
            destination,
            data,
        ) in graph.edges(
            data=True
        ):
            weight = int(
                data.get(
                    "weight",
                    1,
                )
                or 1
            )

            edge_widths.append(
                min(
                    0.8
                    + (
                        weight
                        ** 0.5
                    )
                    * 0.08,
                    4.0,
                )
            )

        nx.draw_networkx_nodes(
            graph,
            position,
            node_size=node_sizes,
            node_color=node_colors,
            alpha=0.94,
            edgecolors="#dbeafe",
            linewidths=0.8,
            ax=axis,
        )

        nx.draw_networkx_edges(
            graph,
            position,
            alpha=0.45,
            edge_color="#64748b",
            width=edge_widths,
            ax=axis,
        )

        nx.draw_networkx_labels(
            graph,
            position,
            font_size=7,
            font_color=TEXT,
            ax=axis,
        )

        axis.set_title(
            title,
            color=TEXT,
            fontsize=13,
            fontweight="bold",
            pad=12,
        )

        legend_items = [
            Patch(
                color=PRIMARY,
                label="Normal",
            ),
            Patch(
                color=DANGER,
                label="Suspicious",
            ),
        ]

        if bssids:
            legend_items.insert(
                1,
                Patch(
                    color=bssid_color,
                    label="BSSID / AP",
                ),
            )

        axis.legend(
            handles=legend_items,
            facecolor=PANEL,
            edgecolor=GRID,
            labelcolor=TEXT,
            loc="upper left",
            bbox_to_anchor=(
                1.01,
                0.98,
            ),
            borderaxespad=0.0,
            framealpha=0.95,
        )

        axis.axis(
            "off"
        )

        # Legend için sağda ayrı alan ayırıyoruz.
        # Böylece renk açıklaması düğümlerin üstünü kapatmaz.
        self.figure.subplots_adjust(
            left=0.03,
            right=0.80,
            top=0.88,
            bottom=0.05,
        )

        self.canvas.draw()

    def update_data(
        self,
        packets,
        alerts,
    ):
        self.figure.clear()

        axis = self.figure.add_subplot(
            111
        )

        _configure_axis(
            self.figure,
            axis,
            "Network Connections",
        )

        suspicious_entities = (
            self._extract_suspicious_entities(
                alerts
            )
        )

        (
            ip_edges,
            ip_nodes,
        ) = self._build_ip_graph_data(
            packets
        )

        if ip_edges:
            self._draw_graph(
                axis=axis,
                edge_counter=ip_edges,
                node_traffic=ip_nodes,
                suspicious_entities=(
                    suspicious_entities
                ),
                title=(
                    "Top Active IP Connections"
                ),
            )
            return

        (
            mac_edges,
            mac_nodes,
            bssids,
        ) = self._build_wireless_graph_data(
            packets
        )

        self._draw_graph(
            axis=axis,
            edge_counter=mac_edges,
            node_traffic=mac_nodes,
            suspicious_entities=(
                suspicious_entities
            ),
            title=(
                "Top Active Wi-Fi MAC / BSSID Connections"
            ),
            bssids=bssids,
            max_nodes=(
                self.MAX_WIRELESS_NODES
            ),
        )
