from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
)


class FlowTab(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(
            self
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
            len(columns)
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

        layout.addWidget(
            self.flow_table
        )

        self.flow_detail = QTextEdit()
        self.flow_detail.setReadOnly(
            True
        )
        self.flow_detail.setPlaceholderText(
            "Detayını görmek için bir flow seçin."
        )

        layout.addWidget(
            self.flow_detail
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
            destination_ip = alert.get(
                "destination_ip"
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

        self.flow_table.setRowCount(
            len(
                self.displayed_flows
            )
        )

        for row, flow in enumerate(
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

            for column, value in enumerate(
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
                        "Bu flow, alarm üreten bir IP ile ilişkilidir."
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

        flow = self.displayed_flows[
            row
        ]

        flags = (
            ", ".join(
                flow.tcp_flags
            )
            if flow.tcp_flags
            else "-"
        )

        text = (
            f"Protocol: {flow.protocol}\n"
            f"Source: {flow.source_ip}:{flow.source_port}\n"
            f"Destination: "
            f"{flow.destination_ip}:{flow.destination_port}\n"
            f"Application: {flow.application_protocol}\n"
            f"Packets: {flow.packet_count}\n"
            f"Bytes: {flow.byte_count}\n"
            f"Forward Packets: {flow.forward_packets}\n"
            f"Reverse Packets: {flow.reverse_packets}\n"
            f"First Seen: {flow.first_seen}\n"
            f"Last Seen: {flow.last_seen}\n"
            f"Duration: {flow.duration:.3f} seconds\n"
            f"TCP Flags: {flags}"
        )

        self.flow_detail.setPlainText(
            text
        )
