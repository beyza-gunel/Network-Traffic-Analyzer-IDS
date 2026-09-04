from collections import Counter

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


class FlowTab(QWidget):

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

        header = QFrame()
        header.setObjectName(
            "detailPanel"
        )
        header_layout = QHBoxLayout(
            header
        )
        header_layout.setContentsMargins(
            14,
            10,
            14,
            10,
        )

        title_box = QVBoxLayout()

        title = QLabel(
            "Flow Analysis"
        )
        title.setObjectName(
            "sectionTitle"
        )

        subtitle = QLabel(
            (
                "İki yönlü ağ konuşmalarını tek flow altında "
                "özetler ve uygulama protokolünü gösterir."
            )
        )
        subtitle.setObjectName(
            "sectionSubtitle"
        )

        title_box.addWidget(
            title
        )
        title_box.addWidget(
            subtitle
        )

        header_layout.addLayout(
            title_box,
            1,
        )

        self.flow_summary = QLabel(
            "0 flows"
        )
        self.flow_summary.setObjectName(
            "engineBadge"
        )

        header_layout.addWidget(
            self.flow_summary
        )

        layout.addWidget(
            header
        )

        self.flow_table = QTableWidget()

        columns = [
            "Protocol",
            "Source",
            "Src Port",
            "Destination",
            "Dst Port",
            "Packets",
            "Bytes",
            "Duration (s)",
            "Forward",
            "Reverse",
            "Application",
            "Status",
        ]

        self.flow_table.setColumnCount(
            len(
                columns
            )
        )
        self.flow_table.setHorizontalHeaderLabels(
            columns
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self.flow_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.flow_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.flow_table.setAlternatingRowColors(
            True
        )

        self.flow_splitter = QSplitter(
            Qt.Vertical
        )

        self.flow_splitter.addWidget(
            self.flow_table
        )

        self.flow_detail = QTextEdit()
        self.flow_detail.setReadOnly(
            True
        )
        self.flow_detail.setPlaceholderText(
            "Detayını görmek için bir flow seçin."
        )

        self.flow_splitter.addWidget(
            self.flow_detail
        )

        self.flow_splitter.setStretchFactor(
            0,
            3
        )
        self.flow_splitter.setStretchFactor(
            1,
            1
        )
        self.flow_splitter.setSizes(
            [
                360,
                150,
            ]
        )

        layout.addWidget(
            self.flow_splitter,
            1
        )

        self.displayed_flows = []

        self.flow_table.cellClicked.connect(
            self.show_flow_detail
        )

    def update_data(
        self,
        flows,
        alerts,
    ):
        suspicious_ips = set()

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
                suspicious_ips.add(
                    str(
                        source_ip
                    )
                )

            if destination_ip:
                suspicious_ips.add(
                    str(
                        destination_ip
                    )
                )

        self.displayed_flows = list(
            flows
        )

        apps = Counter(
            (
                flow.application_protocol
                or flow.protocol
            )
            for flow
            in self.displayed_flows
        )

        summary_parts = [
            f"{len(self.displayed_flows)} flows"
        ]

        for protocol in (
            "HTTP",
            "HTTPS",
            "DNS",
        ):
            if apps.get(
                protocol
            ):
                summary_parts.append(
                    f"{protocol}: {apps[protocol]}"
                )

        self.flow_summary.setText(
            "  |  ".join(
                summary_parts
            )
        )

        self.flow_table.setRowCount(
            len(
                self.displayed_flows
            )
        )

        for (
            row,
            flow,
        ) in enumerate(
            self.displayed_flows
        ):
            source_ip = str(
                flow.source_ip
            )
            destination_ip = str(
                flow.destination_ip
            )

            status = (
                "SUSPICIOUS"
                if (
                    source_ip
                    in suspicious_ips
                    or destination_ip
                    in suspicious_ips
                )
                else "NORMAL"
            )

            values = [
                flow.protocol,
                source_ip,
                flow.source_port,
                destination_ip,
                flow.destination_port,
                flow.packet_count,
                flow.byte_count,
                f"{flow.duration:.3f}",
                flow.forward_packets,
                flow.reverse_packets,
                flow.application_protocol,
                status,
            ]

            for (
                column,
                value,
            ) in enumerate(
                values
            ):
                if value is None:
                    value = ""

                item = QTableWidgetItem(
                    str(
                        value
                    )
                )

                if status == "SUSPICIOUS":
                    item.setToolTip(
                        (
                            "Bu flow, alarm üreten bir "
                            "IP ile ilişkilidir."
                        )
                    )

                self.flow_table.setItem(
                    row,
                    column,
                    item,
                )

    def show_flow_detail(
        self,
        row,
        column,
    ):
        if row >= len(
            self.displayed_flows
        ):
            return

        flow = (
            self.displayed_flows[
                row
            ]
        )

        flags = (
            ", ".join(
                flow.tcp_flags
            )
            if flow.tcp_flags
            else "-"
        )

        text = (
            f"Protocol: {flow.protocol}\n"
            f"Source: "
            f"{flow.source_ip}:{flow.source_port}\n"
            f"Destination: "
            f"{flow.destination_ip}:{flow.destination_port}\n"
            f"Application: "
            f"{flow.application_protocol}\n"
            f"Packets: {flow.packet_count}\n"
            f"Bytes: {flow.byte_count}\n"
            f"Forward Packets: "
            f"{flow.forward_packets}\n"
            f"Reverse Packets: "
            f"{flow.reverse_packets}\n"
            f"First Seen: {flow.first_seen}\n"
            f"Last Seen: {flow.last_seen}\n"
            f"Duration: "
            f"{flow.duration:.3f} seconds\n"
            f"TCP Flags: {flags}"
        )

        self.flow_detail.setPlainText(
            text
        )
