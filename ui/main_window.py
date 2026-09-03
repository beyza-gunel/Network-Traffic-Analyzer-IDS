from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QFileDialog,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QGroupBox,
    QGridLayout,
    QTabWidget,
    QTextEdit,
    QLineEdit,
    QComboBox
)

from workers.analysis_worker import AnalysisWorker
from PySide6.QtCore import QThread
from PySide6.QtCore import Qt

from core.packet_parser import load_pcap
from core.traffic_analyzer import analyze_traffic
from core.detection_engine import run_detection
from core.risk_engine import calculate_risk


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.analysis_thread = None
        self.analysis_worker = None

        self.displayed_packets = []

        # Kullanıcının seçtiği PCAP dosyasının yolu
        self.selected_file = None

        # Analiz edilen paketler
        self.packets = []

        # Bulunan alarmlar
        self.alerts = []

        # Pencere başlığı
        self.setWindowTitle(
            "Network Traffic Analyzer & Intrusion Detection System"
        )

        # Başlangıç pencere boyutu
        self.resize(1250, 750)

        self.create_ui()

    def create_ui(self):

        central_widget = QWidget()

        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        central_widget.setLayout(main_layout)

        # ---------------------------------------
        # BAŞLIK
        # ---------------------------------------

        title = QLabel(
            "NETWORK TRAFFIC ANALYZER & IDS"
        )

        title.setAlignment(Qt.AlignCenter)

        title.setStyleSheet(
            """
            font-size: 24px;
            font-weight: bold;
            padding: 15px;
            """
        )

        main_layout.addWidget(title)

        # ---------------------------------------
        # DOSYA SEÇME ALANI
        # ---------------------------------------

        file_layout = QHBoxLayout()

        self.select_file_button = QPushButton(
            "PCAP DOSYASI SEÇ"
        )

        self.analyze_button = QPushButton(
            "ANALİZİ BAŞLAT"
        )

        self.file_label = QLabel(
            "Henüz dosya seçilmedi."
        )

        file_layout.addWidget(
            self.select_file_button
        )

        file_layout.addWidget(
            self.analyze_button
        )

        file_layout.addWidget(
            self.file_label,
            1
        )

        main_layout.addLayout(file_layout)

        # Buton olayları
        self.select_file_button.clicked.connect(
            self.select_pcap_file
        )

        self.analyze_button.clicked.connect(
            self.start_analysis
        )

        # ---------------------------------------
        # İSTATİSTİK KARTLARI
        # ---------------------------------------

        self.create_statistics_area(
            main_layout
        )

        # ---------------------------------------
        # TAB ALANI
        # ---------------------------------------

        self.tabs = QTabWidget()

        main_layout.addWidget(
            self.tabs
        )

        self.create_packet_tab()
        self.create_alert_tab()    

    def create_statistics_area(self, main_layout):

        statistics_group = QGroupBox(
            "Traffic Statistics"
        )

        statistics_layout = QGridLayout()

        statistics_group.setLayout(
            statistics_layout
        )

        self.total_packets_label = QLabel("0")
        self.unique_ips_label = QLabel("0")
        self.unique_ports_label = QLabel("0")
        self.tcp_packets_label = QLabel("0")
        self.udp_packets_label = QLabel("0")
        self.icmp_packets_label = QLabel("0")
        self.suspicious_label = QLabel("0")
        self.risk_label = QLabel("LOW")

        statistics_layout.addWidget(
            self.create_stat_card(
                "Total Packets",
                self.total_packets_label
            ),
            0,
            0
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "Unique IPs",
                self.unique_ips_label
            ),
            0,
            1
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "Unique Ports",
                self.unique_ports_label
            ),
            0,
            2
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "TCP Packets",
                self.tcp_packets_label
            ),
            0,
            3
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "UDP Packets",
                self.udp_packets_label
            ),
            1,
            0
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "ICMP Packets",
                self.icmp_packets_label
            ),
            1,
            1
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "Suspicious Traffic",
                self.suspicious_label
            ),
            1,
            2
        )

        statistics_layout.addWidget(
            self.create_stat_card(
                "Risk Level",
                self.risk_label
            ),
            1,
            3
        )

        main_layout.addWidget(
            statistics_group
        )    

    def create_stat_card(
        self,
        title,
        value_label
    ):

        card = QGroupBox()

        layout = QVBoxLayout()

        card.setLayout(layout)

        title_label = QLabel(title)

        title_label.setAlignment(
            Qt.AlignCenter
        )

        value_label.setAlignment(
            Qt.AlignCenter
        )

        value_label.setStyleSheet(
            """
            font-size: 24px;
            font-weight: bold;
            """
        )

        layout.addWidget(
            title_label
        )

        layout.addWidget(
            value_label
        )

        return card    

    def create_packet_tab(self):

        packet_widget = QWidget()

        layout = QVBoxLayout()

        packet_widget.setLayout(layout)

        self.packet_table = QTableWidget()

        filter_layout = QHBoxLayout()

        self.source_filter = QLineEdit()

        self.source_filter.setPlaceholderText(
            "Source IP"
        )

        self.destination_filter = QLineEdit()

        self.destination_filter.setPlaceholderText(
            "Destination IP"
        )

        self.port_filter = QLineEdit()

        self.port_filter.setPlaceholderText(
            "Port"
        )

        self.protocol_filter = QComboBox()

        self.protocol_filter.addItems(
            [
                "ALL",
                "TCP",
                "UDP",
                "ICMP",
                "OTHER"
            ]
        )

        self.filter_button = QPushButton(
            "FİLTRELE"
        )

        self.clear_filter_button = QPushButton(
            "TEMİZLE"
        )

        filter_layout.addWidget(
            self.source_filter
        )

        filter_layout.addWidget(
            self.destination_filter
        )

        filter_layout.addWidget(
            self.port_filter
        )

        filter_layout.addWidget(
            self.protocol_filter
        )

        filter_layout.addWidget(
            self.filter_button
        )

        filter_layout.addWidget(
            self.clear_filter_button
        )

        layout.addLayout(
            filter_layout
        )

        columns = [
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Packet Size",
            "TCP Flags",
            "DNS Query"
        ]

        self.filter_button.clicked.connect(
            self.apply_packet_filter
        )

        self.clear_filter_button.clicked.connect(
            self.clear_packet_filter
        )

        self.packet_table.setColumnCount(
            len(columns)
        )

        self.packet_table.setHorizontalHeaderLabels(
            columns
        )

        self.packet_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.packet_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.packet_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        layout.addWidget(
            self.packet_table
        )

        self.packet_detail = QTextEdit()

        self.packet_detail.setReadOnly(
            True
        )

        self.packet_detail.setPlaceholderText(
            "Detayını görmek için bir pakete tıklayın."
        )

        layout.addWidget(
            self.packet_detail
        )

        self.packet_table.cellClicked.connect(
            self.show_packet_detail
        )

        self.tabs.addTab(
            packet_widget,
            "Packets"
        )

    def create_alert_tab(self):

        alert_widget = QWidget()

        layout = QVBoxLayout()

        alert_widget.setLayout(layout)

        self.alert_table = QTableWidget()

        columns = [
            "Alert Type",
            "Source IP",
            "Risk Score",
            "Reason"
        ]

        self.alert_table.setColumnCount(
            len(columns)
        )

        self.alert_table.setHorizontalHeaderLabels(
            columns
        )

        self.alert_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.alert_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.alert_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        layout.addWidget(
            self.alert_table
        )

        self.tabs.addTab(
            alert_widget,
            "Alerts"
        )    

    def select_pcap_file(self):

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "PCAP Dosyası Seç",
            "",
            "PCAP Files (*.pcap *.pcapng)"
        )

        if file_path:

            self.selected_file = file_path

            self.file_label.setText(
                file_path
            )    

    def start_analysis(self):

        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Uyarı",
                "Lütfen önce bir PCAP dosyası seçin."
            )
            return

        # Aynı anda ikinci analiz başlamasın.
        if (
            self.analysis_thread is not None
            and self.analysis_thread.isRunning()
        ):
            QMessageBox.information(
                self,
                "Analiz Devam Ediyor",
                "Mevcut PCAP analizi henüz tamamlanmadı."
            )
            return

        self.statusBar().showMessage(
            "PCAP analizi başlatılıyor..."
        )

        self.analysis_thread = QThread(self)

        self.analysis_worker = AnalysisWorker(
            self.selected_file
        )

        self.analysis_worker.moveToThread(
            self.analysis_thread
        )

        # Thread başlayınca Worker çalışsın.
        self.analysis_thread.started.connect(
            self.analysis_worker.run
        )

        # Worker sinyalleri.
        self.analysis_worker.stage_changed.connect(
            self.on_analysis_stage_changed
        )

        self.analysis_worker.finished.connect(
            self.on_analysis_finished
        )

        self.analysis_worker.failed.connect(
            self.on_analysis_failed
        )

        # İş bitince thread durdurulsun.
        self.analysis_worker.finished.connect(
            self.analysis_thread.quit
        )

        self.analysis_worker.failed.connect(
            self.analysis_thread.quit
        )

        # Worker yalnızca işi bittikten sonra silinsin.
        self.analysis_worker.finished.connect(
            self.analysis_worker.deleteLater
        )

        self.analysis_worker.failed.connect(
            self.analysis_worker.deleteLater
        )

        # Thread gerçekten bittikten sonra cleanup.
        self.analysis_thread.finished.connect(
            self.on_analysis_thread_finished
        )

        self.analysis_thread.start()

    def on_analysis_stage_changed(self, message):
        self.statusBar().showMessage(message)    

    def on_analysis_finished(self, result):

        self.packets = result.packets
        self.displayed_packets = result.packets

        # Yeni Alert modellerini mevcut GUI ile
        # geçici olarak uyumlu hale getiriyoruz.
        self.alerts = []

        for alert in result.alerts:
            self.alerts.append({
                "type": alert.alert_type,
                "source_ip": alert.source_ip,
                "risk_score": alert.risk_score,
                "reason": alert.reason
            })

        risk = {
            "score": result.risk_score,
            "level": result.risk_level
        }

        self.update_statistics(
            result.statistics,
            self.alerts,
            risk
        )

        self.update_packet_table(
            self.packets
        )

        self.update_alert_table(
            self.alerts
        )

        self.statusBar().showMessage(
            f"Analiz tamamlandı - "
            f"{result.total_packets} paket - "
            f"{result.analysis_duration:.3f} saniye"
        )

        QMessageBox.information(
            self,
            "Analiz Tamamlandı",
            (
                f"PCAP analizi başarıyla tamamlandı.\n\n"
                f"Paket sayısı: {result.total_packets}\n"
                f"Risk seviyesi: {result.risk_level}\n"
                f"Analiz süresi: "
                f"{result.analysis_duration:.3f} saniye"
            )
        )

    def on_analysis_failed(self, error_message):

        self.statusBar().showMessage(
            "Analiz başarısız oldu."
        )

        QMessageBox.critical(
            self,
            "PCAP Analiz Hatası",
            (
                "Seçilen PCAP dosyası analiz edilemedi.\n\n"
                f"Detay: {error_message}"
            )
        )

    def on_analysis_thread_finished(self):

        thread = self.analysis_thread

        self.analysis_worker = None
        self.analysis_thread = None

        if thread is not None:
            thread.deleteLater()  


    def update_statistics(
        self,
        statistics,
        alerts,
        risk
    ):

        self.total_packets_label.setText(
            str(
                statistics.get(
                    "total_packets",
                    0
                )
            )
        )

        self.unique_ips_label.setText(
            str(
                statistics.get(
                    "unique_ips",
                    0
                )
            )
        )

        self.unique_ports_label.setText(
            str(
                statistics.get(
                    "unique_ports",
                    0
                )
            )
        )

        self.tcp_packets_label.setText(
            str(
                statistics.get(
                    "tcp_packets",
                    0
                )
            )
        )

        self.udp_packets_label.setText(
            str(
                statistics.get(
                    "udp_packets",
                    0
                )
            )
        )

        self.icmp_packets_label.setText(
            str(
                statistics.get(
                    "icmp_packets",
                    0
                )
            )
        )

        self.suspicious_label.setText(
            str(
                len(alerts)
            )
        )

        self.risk_label.setText(
            risk.get(
                "level",
                "LOW"
            )
        )        

        risk_level = risk.get(
            "level",
            "LOW"
        )

        if risk_level == "LOW":

            self.risk_label.setStyleSheet(
                """
                font-size: 24px;
                font-weight: bold;
                color: green;
                """
            )

        elif risk_level == "MEDIUM":

            self.risk_label.setStyleSheet(
                """
                font-size: 24px;
                font-weight: bold;
                color: orange;
                """
            )

        elif risk_level == "HIGH":

            self.risk_label.setStyleSheet(
                """
                font-size: 24px;
                font-weight: bold;
                color: darkorange;
                """
            )

        elif risk_level == "CRITICAL":

            self.risk_label.setStyleSheet(
                """
                font-size: 24px;
                font-weight: bold;
                color: red;
                """
            )

    def update_packet_table(
        self,
        packets
    ):

        MAX_DISPLAY_PACKETS = 5000

        packets_to_display = packets[
            :MAX_DISPLAY_PACKETS
        ]

        self.displayed_packets = (
            packets_to_display
        )

        self.packet_table.setRowCount(
            len(packets_to_display)
        )

        for row, packet in enumerate(
            packets_to_display
        ):

            values = [
                packet.get("timestamp"),
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("protocol"),
                packet.get("src_port"),
                packet.get("dst_port"),
                packet.get("packet_size"),
                packet.get("tcp_flags"),
                packet.get("dns_query")
            ]

            for column, value in enumerate(
                values
            ):

                if value is None:
                    value = ""

                item = QTableWidgetItem(
                    str(value)
                )

                self.packet_table.setItem(
                    row,
                    column,
                    item
                )

    def update_alert_table(
        self,
        alerts
    ):

        self.alert_table.setRowCount(
            len(alerts)
        )

        for row, alert in enumerate(
            alerts
        ):

            values = [
                alert.get("type"),
                alert.get("source_ip"),
                alert.get("risk_score"),
                alert.get("reason")
            ]

            for column, value in enumerate(
                values
            ):

                if value is None:
                    value = ""

                item = QTableWidgetItem(
                    str(value)
                )

                self.alert_table.setItem(
                    row,
                    column,
                    item
                )            

    def show_packet_detail(
        self,
        row,
        column
    ):

        if row >= len(self.displayed_packets):
            return

        packet = self.displayed_packets[row]

        detail_text = (
            f"Timestamp: {packet.get('timestamp')}\n"
            f"Source IP: {packet.get('src_ip')}\n"
            f"Destination IP: {packet.get('dst_ip')}\n"
            f"Protocol: {packet.get('protocol')}\n"
            f"Source Port: {packet.get('src_port')}\n"
            f"Destination Port: {packet.get('dst_port')}\n"
            f"Packet Size: {packet.get('packet_size')} bytes\n"
            f"TCP Flags: {packet.get('tcp_flags')}\n"
            f"DNS Query: {packet.get('dns_query')}"
        )

        self.packet_detail.setPlainText(
            detail_text
        )      

    def apply_packet_filter(self):

        source_text = (
            self.source_filter
            .text()
            .strip()
        )

        destination_text = (
            self.destination_filter
            .text()
            .strip()
        )

        port_text = (
            self.port_filter
            .text()
            .strip()
        )

        protocol_text = (
            self.protocol_filter
            .currentText()
        )

        filtered_packets = []

        for packet in self.packets:

            src_ip = str(
                packet.get(
                    "src_ip",
                    ""
                )
            )

            dst_ip = str(
                packet.get(
                    "dst_ip",
                    ""
                )
            )

            src_port = str(
                packet.get(
                    "src_port",
                    ""
                )
            )

            dst_port = str(
                packet.get(
                    "dst_port",
                    ""
                )
            )

            protocol = packet.get(
                "protocol",
                ""
            )

            if (
                source_text
                and source_text not in src_ip
            ):
                continue

            if (
                destination_text
                and destination_text not in dst_ip
            ):
                continue

            if port_text:

                if (
                    port_text != src_port
                    and port_text != dst_port
                ):
                    continue

            if (
                protocol_text != "ALL"
                and protocol != protocol_text
            ):
                continue

            filtered_packets.append(
                packet
            )

        self.update_packet_table(
            filtered_packets
        )          

    def clear_packet_filter(self):

        self.source_filter.clear()

        self.destination_filter.clear()

        self.port_filter.clear()

        self.protocol_filter.setCurrentText(
            "ALL"
        )

        self.update_packet_table(
            self.packets
        )    

    def closeEvent(self, event):

        if (
            self.analysis_thread is not None
            and self.analysis_thread.isRunning()
        ):

            self.statusBar().showMessage(
                "Analiz işlemi sonlandırılıyor..."
            )

            self.analysis_thread.quit()

            # Thread'in kapanmasını bekle.
            if not self.analysis_thread.wait(5000):

                self.analysis_thread.requestInterruption()

                self.analysis_thread.quit()

                self.analysis_thread.wait()

        event.accept()    