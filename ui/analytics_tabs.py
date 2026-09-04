from collections import Counter, defaultdict
from datetime import datetime

import networkx as nx

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit
)

from matplotlib.backends.backend_qtagg import (
    FigureCanvasQTAgg as FigureCanvas
)

from matplotlib.figure import Figure


# =========================================================
# TRAFFIC TIMELINE
# =========================================================

class TimelineTab(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self.figure = Figure(
            figsize=(8, 5)
        )

        self.canvas = FigureCanvas(
            self.figure
        )

        layout.addWidget(
            self.canvas
        )

    def update_data(
        self,
        packets,
        alerts
    ):

        self.figure.clear()

        axis = self.figure.add_subplot(111)

        if not packets:

            axis.text(
                0.5,
                0.5,
                "Analiz edilecek trafik bulunamadı.",
                ha="center",
                va="center"
            )

            self.canvas.draw()

            return

        traffic_per_second = Counter()

        for packet in packets:

            timestamp = packet.get(
                "timestamp"
            )

            if timestamp is None:
                continue

            second = int(
                float(timestamp)
            )

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
            linewidth=1.4
        )

        # Alarm zamanlarını timeline üzerinde göster.
        shown_alerts = 0

        for alert in alerts:

            first_seen = alert.get(
                "first_seen"
            )

            if first_seen is None:
                continue

            # Çok fazla çizgi çizerek grafiği
            # okunamaz hale getirmeyelim.
            if shown_alerts >= 20:
                break

            try:

                alert_time = (
                    datetime.fromtimestamp(
                        float(first_seen)
                    )
                )

                axis.axvline(
                    alert_time,
                    linestyle="--",
                    alpha=0.35
                )

                shown_alerts += 1

            except Exception:
                pass

        axis.set_title(
            "Traffic Timeline"
        )

        axis.set_xlabel(
            "Time"
        )

        axis.set_ylabel(
            "Packets / Second"
        )

        axis.grid(
            True,
            alpha=0.25
        )

        self.figure.autofmt_xdate()

        self.figure.tight_layout()

        self.canvas.draw()


# =========================================================
# IP ANALYSIS
# =========================================================

class IPAnalysisTab(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

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
            "Status"
        ]

        self.table.setColumnCount(
            len(columns)
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

        layout.addWidget(
            self.table
        )

        self.detail = QTextEdit()

        self.detail.setReadOnly(
            True
        )

        self.detail.setPlaceholderText(
            "Bir IP adresine tıklayarak analiz detayını görüntüleyin."
        )

        layout.addWidget(
            self.detail
        )

        self.ip_details = {}

        self.table.cellClicked.connect(
            self.show_ip_detail
        )

    def update_data(
        self,
        packets,
        alerts
    ):

        ip_stats = defaultdict(
            lambda: {
                "sent": 0,
                "received": 0,
                "protocols": set(),
                "ports": set(),
                "alerts": []
            }
        )

        # -----------------------------
        # Paketlerden IP istatistikleri
        # -----------------------------

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
                ]["sent"] += 1

                if protocol:

                    ip_stats[
                        src_ip
                    ]["protocols"].add(
                        protocol
                    )

                if src_port is not None:

                    ip_stats[
                        src_ip
                    ]["ports"].add(
                        src_port
                    )

            if dst_ip:

                ip_stats[
                    dst_ip
                ]["received"] += 1

                if protocol:

                    ip_stats[
                        dst_ip
                    ]["protocols"].add(
                        protocol
                    )

                if dst_port is not None:

                    ip_stats[
                        dst_ip
                    ]["ports"].add(
                        dst_port
                    )

        # -----------------------------
        # Alarmları IP'lerle ilişkilendir
        # -----------------------------

        for alert in alerts:

            source_ip = alert.get(
                "source_ip"
            )

            destination_ip = alert.get(
                "destination_ip"
            )

            if source_ip:

                ip_stats[
                    source_ip
                ]["alerts"].append(
                    alert
                )

            if (
                destination_ip
                and destination_ip != source_ip
            ):

                ip_stats[
                    destination_ip
                ]["alerts"].append(
                    alert
                )

        # -----------------------------
        # Tablo
        # -----------------------------

        ordered_ips = sorted(
            ip_stats.items(),
            key=lambda item: (
                item[1]["sent"]
                + item[1]["received"]
            ),
            reverse=True
        )

        self.table.setRowCount(
            len(ordered_ips)
        )

        self.ip_details = {}

        for row, (
            ip_address,
            info
        ) in enumerate(
            ordered_ips
        ):

            total = (
                info["sent"]
                + info["received"]
            )

            alert_count = len(
                info["alerts"]
            )

            max_risk = max(
                (
                    int(
                        alert.get(
                            "risk_score",
                            0
                        )
                    )
                    for alert in info[
                        "alerts"
                    ]
                ),
                default=0
            )

            status = (
                "SUSPICIOUS"
                if alert_count > 0
                else "NORMAL"
            )

            protocols = ", ".join(
                sorted(
                    info["protocols"]
                )
            )

            values = [
                ip_address,
                info["sent"],
                info["received"],
                total,
                protocols,
                len(info["ports"]),
                alert_count,
                max_risk,
                status
            ]

            for column, value in enumerate(
                values
            ):

                self.table.setItem(
                    row,
                    column,
                    QTableWidgetItem(
                        str(value)
                    )
                )

            self.ip_details[
                ip_address
            ] = info

    def show_ip_detail(
        self,
        row,
        column
    ):

        item = self.table.item(
            row,
            0
        )

        if item is None:
            return

        ip_address = item.text()

        info = self.ip_details.get(
            ip_address
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
                "- Bu IP ile ilişkilendirilmiş güvenlik alarmı yok."
            )

        text = (
            f"IP Address: {ip_address}\n"
            f"Sent Packets: {info['sent']}\n"
            f"Received Packets: {info['received']}\n"
            f"Protocols: {', '.join(sorted(info['protocols']))}\n"
            f"Unique Ports: {len(info['ports'])}\n\n"
            f"Why Suspicious?\n"
            + "\n".join(
                alert_lines
            )
        )

        self.detail.setPlainText(
            text
        )


# =========================================================
# NETWORK CONNECTION GRAPH
# =========================================================

class NetworkGraphTab(QWidget):

    MAX_NODES = 40

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self.figure = Figure(
            figsize=(8, 6)
        )

        self.canvas = FigureCanvas(
            self.figure
        )

        layout.addWidget(
            self.canvas
        )

    def update_data(
        self,
        packets,
        alerts
    ):

        self.figure.clear()

        axis = self.figure.add_subplot(111)

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

            edge = tuple(
                sorted(
                    (
                        src_ip,
                        dst_ip
                    )
                )
            )

            edge_counter[
                edge
            ] += 1

            node_traffic[
                src_ip
            ] += 1

            node_traffic[
                dst_ip
            ] += 1

        if not edge_counter:

            axis.text(
                0.5,
                0.5,
                "IP bağlantısı bulunamadı.",
                ha="center",
                va="center"
            )

            axis.axis(
                "off"
            )

            self.canvas.draw()

            return

        top_nodes = {
            node
            for node, count
            in node_traffic.most_common(
                self.MAX_NODES
            )
        }

        graph = nx.Graph()

        for (
            source,
            destination
        ), packet_count in edge_counter.items():

            if (
                source not in top_nodes
                or destination not in top_nodes
            ):
                continue

            graph.add_edge(
                source,
                destination,
                weight=packet_count
            )

        suspicious_ips = set()

        for alert in alerts:

            source_ip = alert.get(
                "source_ip"
            )

            destination_ip = alert.get(
                "destination_ip"
            )

            if source_ip:
                suspicious_ips.add(
                    source_ip
                )

            if destination_ip:
                suspicious_ips.add(
                    destination_ip
                )

        position = nx.spring_layout(
            graph,
            seed=42
        )

        node_sizes = [
            min(
                500
                + node_traffic[
                    node
                ] * 2,
                3000
            )
            for node in graph.nodes
        ]

        node_colors = [
            "#ef4444"
            if node in suspicious_ips
            else "#38bdf8"
            for node in graph.nodes
        ]

        nx.draw_networkx_nodes(
            graph,
            position,
            node_size=node_sizes,
            node_color=node_colors,
            alpha=0.85,
            ax=axis
        )

        nx.draw_networkx_edges(
            graph,
            position,
            alpha=0.35,
            ax=axis
        )

        nx.draw_networkx_labels(
            graph,
            position,
            font_size=7,
            ax=axis
        )

        axis.set_title(
            "Network Connection Graph - Top Active IPs"
        )

        axis.axis(
            "off"
        )

        self.figure.tight_layout()

        self.canvas.draw()