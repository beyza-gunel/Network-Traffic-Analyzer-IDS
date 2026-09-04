from collections import Counter, defaultdict
from datetime import datetime

import networkx as nx

from PySide6.QtCore import Qt

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


class TimelineTab(QWidget):

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
                "Traffic Timeline",
                (
                    "Paket yoğunluğunu zaman ekseninde "
                    "ve alarm başlangıçlarını birlikte gösterir."
                ),
            )
        )

        self.figure = Figure(
            figsize=(8, 5),
            facecolor=PANEL,
        )

        self.canvas = FigureCanvas(
            self.figure
        )

        layout.addWidget(
            self.canvas,
            1,
        )

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
            "Packets per Second",
        )

        if not packets:
            axis.text(
                0.5,
                0.5,
                "Analiz edilecek trafik bulunamadı.",
                color=MUTED,
                ha="center",
                va="center",
            )
            self.canvas.draw()
            return

        traffic_per_second = (
            Counter()
        )

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

        values = [
            traffic_per_second[
                second
            ]
            for second in seconds
        ]

        times = [
            datetime.fromtimestamp(
                second
            )
            for second in seconds
        ]

        axis.plot(
            times,
            values,
            linewidth=1.8,
            color=PRIMARY,
        )

        axis.fill_between(
            times,
            values,
            alpha=0.10,
            color=PRIMARY,
        )

        shown_alerts = 0

        for alert in alerts:
            first_seen = alert.get(
                "first_seen"
            )

            if first_seen is None:
                continue

            if shown_alerts >= 20:
                break

            try:
                alert_time = (
                    datetime.fromtimestamp(
                        float(
                            first_seen
                        )
                    )
                )

                axis.axvline(
                    alert_time,
                    linestyle="--",
                    alpha=0.55,
                    linewidth=1.0,
                    color=DANGER,
                )

                shown_alerts += 1

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
            alpha=0.28,
            color=GRID,
        )

        self.figure.autofmt_xdate()
        self.figure.tight_layout(
            pad=1.6
        )
        self.canvas.draw()


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
                    "Aktif IP adreslerini, protokolleri, portları "
                    "ve alarm ilişkilerini özetler."
                ),
            )
        )

        self.table = QTableWidget()

        columns = [
            "IP Address",
            "Sent",
            "Received",
            "Total",
            "Protocols",
            "Unique Ports",
            "Alerts",
            "Max Risk",
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
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
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
                "analiz detayını görüntüleyin."
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
            1
        )
        self.detail_splitter.setSizes(
            [
                360,
                150,
            ]
        )

        layout.addWidget(
            self.detail_splitter,
            1
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
                "alerts": [],
            }
        )

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

            if src_ip:
                ip_stats[
                    src_ip
                ][
                    "sent"
                ] += 1

                if protocol:
                    ip_stats[
                        src_ip
                    ][
                        "protocols"
                    ].add(
                        protocol
                    )

                if (
                    src_port
                    is not None
                ):
                    ip_stats[
                        src_ip
                    ][
                        "ports"
                    ].add(
                        src_port
                    )

            if dst_ip:
                ip_stats[
                    dst_ip
                ][
                    "received"
                ] += 1

                if protocol:
                    ip_stats[
                        dst_ip
                    ][
                        "protocols"
                    ].add(
                        protocol
                    )

                if (
                    dst_port
                    is not None
                ):
                    ip_stats[
                        dst_ip
                    ][
                        "ports"
                    ].add(
                        dst_port
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
            total = (
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

            max_risk = max(
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
                    info[
                        "protocols"
                    ]
                )
            )

            values = [
                ip_address,
                info[
                    "sent"
                ],
                info[
                    "received"
                ],
                total,
                protocols,
                len(
                    info[
                        "ports"
                    ]
                ),
                alert_count,
                max_risk,
                status,
            ]

            for (
                column,
                value,
            ) in enumerate(
                values
            ):
                item = (
                    QTableWidgetItem(
                        str(
                            value
                        )
                    )
                )

                if (
                    column == 8
                    and status
                    == "SUSPICIOUS"
                ):
                    item.setForeground(
                        DANGER
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

        info = (
            self.ip_details.get(
                ip_address
            )
        )

        if not info:
            return

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

        text = (
            f"IP Address: {ip_address}\n"
            f"Sent Packets: {info['sent']}\n"
            f"Received Packets: {info['received']}\n"
            f"Protocols: "
            f"{', '.join(sorted(info['protocols']))}\n"
            f"Unique Ports: {len(info['ports'])}\n\n"
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
