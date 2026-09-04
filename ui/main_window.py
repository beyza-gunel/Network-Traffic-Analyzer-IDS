from pathlib import Path

from PySide6.QtCore import Qt, QThread, QDateTime
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
    QComboBox,
    QDateTimeEdit,
    QCheckBox,
)

from workers.analysis_worker import AnalysisWorker
from ui.analytics_tabs import (
    TimelineTab,
    IPAnalysisTab,
    NetworkGraphTab,
)
from ui.flow_tab import FlowTab
from services.report_service import (
    build_report_data,
    export_json,
    export_html,
    export_pdf,
)
from utils.security import (
    PcapValidationError,
    validate_pcap_file,
    format_file_size,
)


class MainWindow(QMainWindow):

    MAX_DISPLAY_PACKETS = 5000

    def __init__(self):
        super().__init__()

        self.analysis_thread = None
        self.analysis_worker = None

        self.selected_file = None
        self.packets = []
        self.displayed_packets = []
        self.alerts = []
        self.displayed_alerts = []
        self.flows = []

        self.current_statistics = {}
        self.current_risk_score = 0
        self.current_risk_level = "LOW"
        self.current_risk_breakdown = []

        self.setWindowTitle(
            "Network Traffic Analyzer & Intrusion Detection System"
        )
        self.resize(1250, 750)

        self.create_ui()

    # =========================================================
    # UI
    # =========================================================

    def create_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(
            central_widget
        )

        main_layout = QVBoxLayout(
            central_widget
        )

        title = QLabel(
            "NETWORK TRAFFIC ANALYZER & IDS"
        )
        title.setAlignment(
            Qt.AlignCenter
        )
        title.setStyleSheet(
            """
            font-size: 24px;
            font-weight: bold;
            padding: 15px;
            """
        )
        main_layout.addWidget(
            title
        )

        # -----------------------------------------------------
        # Dosya / analiz / rapor
        # -----------------------------------------------------

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

        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems(
            [
                "JSON",
                "HTML",
                "PDF",
            ]
        )

        self.export_report_button = QPushButton(
            "RAPORU DIŞA AKTAR"
        )
        self.export_report_button.setEnabled(
            False
        )

        file_layout.addWidget(
            self.select_file_button
        )
        file_layout.addWidget(
            self.analyze_button
        )
        file_layout.addWidget(
            self.file_label,
            1,
        )
        file_layout.addWidget(
            self.report_format_combo
        )
        file_layout.addWidget(
            self.export_report_button
        )

        main_layout.addLayout(
            file_layout
        )

        self.select_file_button.clicked.connect(
            self.select_pcap_file
        )
        self.analyze_button.clicked.connect(
            self.start_analysis
        )
        self.export_report_button.clicked.connect(
            self.export_report
        )

        self.create_statistics_area(
            main_layout
        )

        self.tabs = QTabWidget()
        main_layout.addWidget(
            self.tabs
        )

        self.create_packet_tab()
        self.create_alert_tab()

        self.timeline_tab = TimelineTab()
        self.ip_analysis_tab = IPAnalysisTab()
        self.network_graph_tab = NetworkGraphTab()
        self.flow_tab = FlowTab()

        self.tabs.addTab(
            self.timeline_tab,
            "Timeline",
        )
        self.tabs.addTab(
            self.ip_analysis_tab,
            "IP Analysis",
        )
        self.tabs.addTab(
            self.network_graph_tab,
            "Network Graph",
        )
        self.tabs.addTab(
            self.flow_tab,
            "Flows",
        )

        self.analytics_loaded = {
            "timeline": False,
            "ip": False,
            "graph": False,
            "flow": False,
        }

        self.tabs.currentChanged.connect(
            self.on_tab_changed
        )

    # =========================================================
    # DASHBOARD
    # =========================================================

    def create_statistics_area(
        self,
        main_layout,
    ):
        statistics_group = QGroupBox(
            "Traffic Statistics"
        )

        statistics_layout = QGridLayout()
        statistics_group.setLayout(
            statistics_layout
        )

        self.total_packets_label = QLabel(
            "0"
        )
        self.unique_ips_label = QLabel(
            "0"
        )
        self.unique_ports_label = QLabel(
            "0"
        )
        self.tcp_connections_label = QLabel(
            "0"
        )
        self.udp_packets_label = QLabel(
            "0"
        )
        self.critical_alerts_label = QLabel(
            "0"
        )
        self.suspicious_label = QLabel(
            "0"
        )
        self.risk_label = QLabel(
            "LOW"
        )

        cards = [
            (
                "Total Packets",
                self.total_packets_label,
                0,
                0,
            ),
            (
                "Unique IPs",
                self.unique_ips_label,
                0,
                1,
            ),
            (
                "Unique Ports",
                self.unique_ports_label,
                0,
                2,
            ),
            (
                "TCP Connections",
                self.tcp_connections_label,
                0,
                3,
            ),
            (
                "UDP Traffic",
                self.udp_packets_label,
                1,
                0,
            ),
            (
                "Critical Alerts",
                self.critical_alerts_label,
                1,
                1,
            ),
            (
                "Suspicious Traffic",
                self.suspicious_label,
                1,
                2,
            ),
            (
                "Risk Level",
                self.risk_label,
                1,
                3,
            ),
        ]

        for (
            title,
            label,
            row,
            column,
        ) in cards:
            statistics_layout.addWidget(
                self.create_stat_card(
                    title,
                    label,
                ),
                row,
                column,
            )

        main_layout.addWidget(
            statistics_group
        )

    def create_stat_card(
        self,
        title,
        value_label,
    ):
        card = QGroupBox()
        layout = QVBoxLayout(
            card
        )

        title_label = QLabel(
            title
        )
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

    # =========================================================
    # PACKETS TAB
    # =========================================================

    def create_packet_tab(
        self,
    ):
        packet_widget = QWidget()
        layout = QVBoxLayout(
            packet_widget
        )

        # -----------------------------------------------------
        # Temel filtreler
        # -----------------------------------------------------

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
                "ARP",
                "OTHER",
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

        # -----------------------------------------------------
        # Tarih / saat filtresi
        # -----------------------------------------------------

        time_filter_layout = QHBoxLayout()

        self.time_filter_check = QCheckBox(
            "Tarih/Saat filtresi"
        )

        self.start_time_edit = QDateTimeEdit()
        self.start_time_edit.setDisplayFormat(
            "yyyy-MM-dd HH:mm:ss"
        )
        self.start_time_edit.setCalendarPopup(
            True
        )
        self.start_time_edit.setEnabled(
            False
        )

        self.end_time_edit = QDateTimeEdit()
        self.end_time_edit.setDisplayFormat(
            "yyyy-MM-dd HH:mm:ss"
        )
        self.end_time_edit.setCalendarPopup(
            True
        )
        self.end_time_edit.setEnabled(
            False
        )

        time_filter_layout.addWidget(
            self.time_filter_check
        )
        time_filter_layout.addWidget(
            QLabel(
                "Başlangıç:"
            )
        )
        time_filter_layout.addWidget(
            self.start_time_edit
        )
        time_filter_layout.addWidget(
            QLabel(
                "Bitiş:"
            )
        )
        time_filter_layout.addWidget(
            self.end_time_edit
        )
        time_filter_layout.addStretch(
            1
        )

        layout.addLayout(
            time_filter_layout
        )

        self.time_filter_check.toggled.connect(
            self.start_time_edit.setEnabled
        )
        self.time_filter_check.toggled.connect(
            self.end_time_edit.setEnabled
        )

        # -----------------------------------------------------
        # Paket tablosu
        # -----------------------------------------------------

        self.packet_table = QTableWidget()

        columns = [
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Packet Size",
            "TCP Flags",
            "DNS Query",
        ]

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

        self.filter_button.clicked.connect(
            self.apply_packet_filter
        )
        self.clear_filter_button.clicked.connect(
            self.clear_packet_filter
        )
        self.packet_table.cellClicked.connect(
            self.show_packet_detail
        )

        self.tabs.addTab(
            packet_widget,
            "Packets",
        )

    # =========================================================
    # ALERTS TAB
    # =========================================================

    def create_alert_tab(
        self,
    ):
        alert_widget = QWidget()
        layout = QVBoxLayout(
            alert_widget
        )

        # -----------------------------------------------------
        # Alert filtreleri
        # -----------------------------------------------------

        alert_filter_layout = QHBoxLayout()

        self.alert_type_filter = QComboBox()
        self.alert_type_filter.addItem(
            "ALL"
        )

        self.alert_risk_filter = QComboBox()
        self.alert_risk_filter.addItems(
            [
                "ALL",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ]
        )

        self.alert_ip_filter = QLineEdit()
        self.alert_ip_filter.setPlaceholderText(
            "Source / Destination IP"
        )

        self.alert_filter_button = QPushButton(
            "ALARM FİLTRELE"
        )
        self.alert_clear_filter_button = QPushButton(
            "TEMİZLE"
        )

        alert_filter_layout.addWidget(
            QLabel(
                "Alert Type:"
            )
        )
        alert_filter_layout.addWidget(
            self.alert_type_filter
        )
        alert_filter_layout.addWidget(
            QLabel(
                "Risk:"
            )
        )
        alert_filter_layout.addWidget(
            self.alert_risk_filter
        )
        alert_filter_layout.addWidget(
            self.alert_ip_filter
        )
        alert_filter_layout.addWidget(
            self.alert_filter_button
        )
        alert_filter_layout.addWidget(
            self.alert_clear_filter_button
        )

        layout.addLayout(
            alert_filter_layout
        )

        # -----------------------------------------------------
        # Alert tablosu
        # -----------------------------------------------------

        self.alert_table = QTableWidget()

        columns = [
            "Alert Type",
            "Level",
            "Source IP",
            "Destination IP",
            "Risk Score",
            "Reason",
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

        self.alert_detail = QTextEdit()
        self.alert_detail.setReadOnly(
            True
        )
        self.alert_detail.setPlaceholderText(
            "Detayını görmek için bir alarma tıklayın."
        )

        layout.addWidget(
            self.alert_detail
        )

        self.alert_filter_button.clicked.connect(
            self.apply_alert_filter
        )
        self.alert_clear_filter_button.clicked.connect(
            self.clear_alert_filter
        )
        self.alert_table.cellClicked.connect(
            self.show_alert_detail
        )

        self.tabs.addTab(
            alert_widget,
            "Alerts",
        )

    # =========================================================
    # DOSYA SEÇME / ANALİZ
    # =========================================================

    def select_pcap_file(
        self,
    ):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "PCAP Dosyası Seç",
            "",
            "PCAP Files (*.pcap *.pcapng)",
        )

        if file_path:
            try:
                validation = (
                    validate_pcap_file(
                        file_path
                    )
                )

            except PcapValidationError as error:
                self.selected_file = None

                QMessageBox.warning(
                    self,
                    "Geçersiz PCAP Dosyası",
                    str(
                        error
                    ),
                )

                return

            self.selected_file = str(
                validation.path
            )

            self.file_label.setText(
                self.selected_file
            )

            if validation.is_large:
                QMessageBox.information(
                    self,
                    "Büyük PCAP Dosyası",
                    (
                        "Seçilen dosya büyük bir "
                        "PCAP dosyasıdır.\n\n"
                        f"Boyut: "
                        f"{format_file_size(validation.size_bytes)}\n"
                        "Dosya PcapReader ile sıralı "
                        "olarak okunacaktır. Analiz "
                        "süresi dosya boyutuna göre "
                        "uzayabilir."
                    ),
                )

    def start_analysis(
        self,
    ):
        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Uyarı",
                "Lütfen önce bir PCAP dosyası seçin.",
            )
            return

        try:
            validate_pcap_file(
                self.selected_file
            )

        except PcapValidationError as error:
            QMessageBox.warning(
                self,
                "PCAP Doğrulama Hatası",
                str(
                    error
                ),
            )
            return

        if (
            self.analysis_thread is not None
            and self.analysis_thread.isRunning()
        ):
            QMessageBox.information(
                self,
                "Analiz Devam Ediyor",
                "Mevcut PCAP analizi henüz tamamlanmadı.",
            )
            return

        self.analyze_button.setEnabled(
            False
        )
        self.export_report_button.setEnabled(
            False
        )

        self.statusBar().showMessage(
            "PCAP analizi başlatılıyor..."
        )

        self.analysis_thread = QThread(
            self
        )
        self.analysis_worker = AnalysisWorker(
            self.selected_file
        )

        self.analysis_worker.moveToThread(
            self.analysis_thread
        )

        self.analysis_thread.started.connect(
            self.analysis_worker.run
        )

        self.analysis_worker.stage_changed.connect(
            self.on_analysis_stage_changed
        )
        self.analysis_worker.finished.connect(
            self.on_analysis_finished
        )
        self.analysis_worker.failed.connect(
            self.on_analysis_failed
        )

        self.analysis_worker.finished.connect(
            self.analysis_thread.quit
        )
        self.analysis_worker.failed.connect(
            self.analysis_thread.quit
        )

        self.analysis_worker.finished.connect(
            self.analysis_worker.deleteLater
        )
        self.analysis_worker.failed.connect(
            self.analysis_worker.deleteLater
        )

        self.analysis_thread.finished.connect(
            self.on_analysis_thread_finished
        )

        self.analysis_thread.start()

    def on_analysis_stage_changed(
        self,
        message,
    ):
        self.statusBar().showMessage(
            message
        )

    def on_analysis_finished(
        self,
        result,
    ):
        self.packets = (
            result.packets
        )
        self.flows = list(
            result.flows
            or []
        )
        self.displayed_packets = []

        self.current_statistics = dict(
            result.statistics
        )
        self.current_risk_score = (
            result.risk_score
        )
        self.current_risk_level = (
            result.risk_level
        )
        self.current_risk_breakdown = list(
            result.risk_breakdown
            or []
        )

        self.alerts = []

        for alert in result.alerts:
            self.alerts.append(
                {
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "confidence": alert.confidence,
                    "reason": alert.reason,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "source_port": alert.source_port,
                    "destination_port": alert.destination_port,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "packet_count": alert.packet_count,
                    "evidence": alert.evidence or [],
                }
            )

        risk = {
            "score": result.risk_score,
            "level": result.risk_level,
        }

        self.update_statistics(
            result.statistics,
            self.alerts,
            risk,
        )
        self.update_packet_table(
            self.packets
        )
        self.update_alert_table(
            self.alerts
        )

        self.configure_time_filter_range()
        self.refresh_alert_type_filter()

        self.analytics_loaded = {
            "timeline": False,
            "ip": False,
            "graph": False,
            "flow": False,
        }

        self.on_tab_changed(
            self.tabs.currentIndex()
        )

        self.export_report_button.setEnabled(
            True
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
                "PCAP analizi başarıyla tamamlandı.\n\n"
                f"Paket sayısı: {result.total_packets}\n"
                f"Risk skoru: {result.risk_score}\n"
                f"Risk seviyesi: {result.risk_level}\n"
                f"Analiz süresi: "
                f"{result.analysis_duration:.3f} saniye"
            ),
        )

    def on_analysis_failed(
        self,
        error_message,
    ):
        self.statusBar().showMessage(
            "Analiz başarısız oldu."
        )

        QMessageBox.critical(
            self,
            "PCAP Analiz Hatası",
            (
                "Seçilen PCAP dosyası analiz edilemedi.\n\n"
                f"Detay: {error_message}"
            ),
        )

    def on_analysis_thread_finished(
        self,
    ):
        thread = (
            self.analysis_thread
        )

        self.analysis_worker = None
        self.analysis_thread = None

        self.analyze_button.setEnabled(
            True
        )

        if (
            self.packets
            and self.current_statistics
        ):
            self.export_report_button.setEnabled(
                True
            )

        if thread is not None:
            thread.deleteLater()

    # =========================================================
    # ANALYTICS
    # =========================================================

    def on_tab_changed(
        self,
        index,
    ):
        if not self.packets:
            return

        current_widget = (
            self.tabs.widget(
                index
            )
        )

        if (
            current_widget
            is self.timeline_tab
            and not self.analytics_loaded[
                "timeline"
            ]
        ):
            self.timeline_tab.update_data(
                self.packets,
                self.alerts,
            )
            self.analytics_loaded[
                "timeline"
            ] = True

        elif (
            current_widget
            is self.ip_analysis_tab
            and not self.analytics_loaded[
                "ip"
            ]
        ):
            self.ip_analysis_tab.update_data(
                self.packets,
                self.alerts,
            )
            self.analytics_loaded[
                "ip"
            ] = True

        elif (
            current_widget
            is self.network_graph_tab
            and not self.analytics_loaded[
                "graph"
            ]
        ):
            self.network_graph_tab.update_data(
                self.packets,
                self.alerts,
            )
            self.analytics_loaded[
                "graph"
            ] = True

        elif (
            current_widget
            is self.flow_tab
            and not self.analytics_loaded[
                "flow"
            ]
        ):
            self.flow_tab.update_data(
                self.flows,
                self.alerts,
            )
            self.analytics_loaded[
                "flow"
            ] = True

    # =========================================================
    # İSTATİSTİKLER
    # =========================================================

    def update_statistics(
        self,
        statistics,
        alerts,
        risk,
    ):
        self.total_packets_label.setText(
            str(
                statistics.get(
                    "total_packets",
                    0,
                )
            )
        )

        self.unique_ips_label.setText(
            str(
                statistics.get(
                    "unique_ips",
                    0,
                )
            )
        )

        self.unique_ports_label.setText(
            str(
                statistics.get(
                    "unique_ports",
                    0,
                )
            )
        )

        self.tcp_connections_label.setText(
            str(
                statistics.get(
                    "tcp_connections",
                    0,
                )
            )
        )

        self.udp_packets_label.setText(
            str(
                statistics.get(
                    "udp_packets",
                    0,
                )
            )
        )

        critical_alert_count = sum(
            1
            for alert in alerts
            if self.get_alert_level(
                alert
            )
            == "CRITICAL"
        )

        self.critical_alerts_label.setText(
            str(
                critical_alert_count
            )
        )

        self.suspicious_label.setText(
            str(
                len(alerts)
            )
        )

        risk_level = str(
            risk.get(
                "level",
                "LOW",
            )
        ).upper()

        self.risk_label.setText(
            risk_level
        )

        risk_colors = {
            "LOW": "green",
            "MEDIUM": "orange",
            "HIGH": "darkorange",
            "CRITICAL": "red",
        }

        color = risk_colors.get(
            risk_level,
            "white",
        )

        self.risk_label.setStyleSheet(
            f"""
            font-size: 24px;
            font-weight: bold;
            color: {color};
            """
        )

    # =========================================================
    # PACKET TABLOSU / DETAY
    # =========================================================

    def update_packet_table(
        self,
        packets,
    ):
        packets_to_display = packets[
            : self.MAX_DISPLAY_PACKETS
        ]

        self.displayed_packets = (
            packets_to_display
        )

        self.packet_table.setUpdatesEnabled(
            False
        )

        try:
            self.packet_table.setRowCount(
                len(
                    packets_to_display
                )
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
                    packet.get("dns_query"),
                ]

                for (
                    column,
                    value,
                ) in enumerate(
                    values
                ):
                    if value is None:
                        value = ""

                    self.packet_table.setItem(
                        row,
                        column,
                        QTableWidgetItem(
                            str(value)
                        ),
                    )
        finally:
            self.packet_table.setUpdatesEnabled(
                True
            )

    def show_packet_detail(
        self,
        row,
        column,
    ):
        if row >= len(
            self.displayed_packets
        ):
            return

        packet = (
            self.displayed_packets[
                row
            ]
        )

        detail_text = (
            f"Timestamp: {packet.get('timestamp')}\n"
            f"Source IP: {packet.get('src_ip')}\n"
            f"Destination IP: {packet.get('dst_ip')}\n"
            f"Source MAC: {packet.get('src_mac')}\n"
            f"Destination MAC: {packet.get('dst_mac')}\n"
            f"Protocol: {packet.get('protocol')}\n"
            f"Application Protocol: {packet.get('application_protocol')}\n"
            f"Source Port: {packet.get('src_port')}\n"
            f"Destination Port: {packet.get('dst_port')}\n"
            f"Packet Size: {packet.get('packet_size')} bytes\n"
            f"TCP Flags: {packet.get('tcp_flags')}\n"
            f"DNS Query: {packet.get('dns_query')}\n"
            f"HTTP Method: {packet.get('http_method')}\n"
            f"HTTP Host: {packet.get('http_host')}\n"
            f"HTTP Path: {packet.get('http_path')}\n"
            f"HTTPS Detected: {packet.get('https_detected')}\n"
            f"ICMP Type: {packet.get('icmp_type')}\n"
            f"ICMP Code: {packet.get('icmp_code')}\n"
            f"SSID: {packet.get('ssid')}\n"
            f"BSSID: {packet.get('bssid')}\n"
            f"Wi-Fi Channel: {packet.get('wifi_channel')}\n"
            f"WLAN Type/Subtype: "
            f"{packet.get('wlan_type')}/"
            f"{packet.get('wlan_subtype')}\n"
            f"EAPOL: {packet.get('eapol')}\n"
            f"EAPOL Key Number: "
            f"{packet.get('eapol_key_number')}\n"
            f"EAPOL Replay Counter: "
            f"{packet.get('eapol_replay_counter')}"
        )

        self.packet_detail.setPlainText(
            detail_text
        )

    # =========================================================
    # PACKET FILTERS
    # =========================================================

    def configure_time_filter_range(
        self,
    ):
        timestamps = []

        for packet in self.packets:
            timestamp = packet.get(
                "timestamp"
            )

            if timestamp is None:
                continue

            try:
                timestamps.append(
                    float(
                        timestamp
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

        if not timestamps:
            self.time_filter_check.setChecked(
                False
            )
            return

        minimum = int(
            min(
                timestamps
            )
        )
        maximum = int(
            max(
                timestamps
            )
        )

        self.start_time_edit.setDateTime(
            QDateTime.fromSecsSinceEpoch(
                minimum
            )
        )
        self.end_time_edit.setDateTime(
            QDateTime.fromSecsSinceEpoch(
                maximum
            )
        )

    def apply_packet_filter(
        self,
    ):
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

        use_time_filter = (
            self.time_filter_check
            .isChecked()
        )

        start_timestamp = (
            self.start_time_edit
            .dateTime()
            .toSecsSinceEpoch()
        )

        end_timestamp = (
            self.end_time_edit
            .dateTime()
            .toSecsSinceEpoch()
        )

        if (
            use_time_filter
            and start_timestamp
            > end_timestamp
        ):
            QMessageBox.warning(
                self,
                "Geçersiz Tarih/Saat Aralığı",
                (
                    "Başlangıç zamanı bitiş "
                    "zamanından büyük olamaz."
                ),
            )
            return

        filtered_packets = []

        for packet in self.packets:
            src_ip = str(
                packet.get(
                    "src_ip",
                    "",
                )
                or ""
            )

            dst_ip = str(
                packet.get(
                    "dst_ip",
                    "",
                )
                or ""
            )

            src_port = str(
                packet.get(
                    "src_port",
                    "",
                )
                or ""
            )

            dst_port = str(
                packet.get(
                    "dst_port",
                    "",
                )
                or ""
            )

            protocol = str(
                packet.get(
                    "protocol",
                    "",
                )
                or ""
            )

            if (
                source_text
                and source_text
                not in src_ip
            ):
                continue

            if (
                destination_text
                and destination_text
                not in dst_ip
            ):
                continue

            if (
                port_text
                and port_text
                != src_port
                and port_text
                != dst_port
            ):
                continue

            if (
                protocol_text
                != "ALL"
                and protocol
                != protocol_text
            ):
                continue

            if use_time_filter:
                timestamp = packet.get(
                    "timestamp"
                )

                if timestamp is None:
                    continue

                try:
                    timestamp = float(
                        timestamp
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

                if (
                    timestamp
                    < start_timestamp
                    or timestamp
                    > end_timestamp
                ):
                    continue

            filtered_packets.append(
                packet
            )

        self.update_packet_table(
            filtered_packets
        )

        self.statusBar().showMessage(
            f"Filtre sonucu: "
            f"{len(filtered_packets)} paket "
            f"(tabloda en fazla "
            f"{self.MAX_DISPLAY_PACKETS} gösterilir)"
        )

    def clear_packet_filter(
        self,
    ):
        self.source_filter.clear()
        self.destination_filter.clear()
        self.port_filter.clear()
        self.protocol_filter.setCurrentText(
            "ALL"
        )
        self.time_filter_check.setChecked(
            False
        )

        self.configure_time_filter_range()

        self.update_packet_table(
            self.packets
        )

        self.statusBar().showMessage(
            "Paket filtreleri temizlendi."
        )

    # =========================================================
    # ALERT TABLOSU / FILTER / DETAY
    # =========================================================

    def get_alert_level(
        self,
        alert,
    ):
        severity = str(
            alert.get(
                "severity",
                "",
            )
            or ""
        ).upper()

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

    def refresh_alert_type_filter(
        self,
    ):
        selected = (
            self.alert_type_filter
            .currentText()
        )

        alert_types = sorted(
            {
                str(
                    alert.get(
                        "type",
                        "UNKNOWN",
                    )
                )
                for alert in self.alerts
            }
        )

        self.alert_type_filter.blockSignals(
            True
        )

        self.alert_type_filter.clear()
        self.alert_type_filter.addItem(
            "ALL"
        )
        self.alert_type_filter.addItems(
            alert_types
        )

        index = (
            self.alert_type_filter
            .findText(
                selected
            )
        )

        if index >= 0:
            self.alert_type_filter.setCurrentIndex(
                index
            )

        self.alert_type_filter.blockSignals(
            False
        )

    def update_alert_table(
        self,
        alerts,
    ):
        self.displayed_alerts = list(
            alerts
        )

        self.alert_table.setRowCount(
            len(
                self.displayed_alerts
            )
        )

        for (
            row,
            alert,
        ) in enumerate(
            self.displayed_alerts
        ):
            values = [
                alert.get("type"),
                self.get_alert_level(
                    alert
                ),
                alert.get("source_ip"),
                alert.get(
                    "destination_ip"
                ),
                alert.get("risk_score"),
                alert.get("reason"),
            ]

            for (
                column,
                value,
            ) in enumerate(
                values
            ):
                if value is None:
                    value = ""

                self.alert_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(
                        str(value)
                    ),
                )

    def apply_alert_filter(
        self,
    ):
        alert_type = (
            self.alert_type_filter
            .currentText()
        )

        risk_level = (
            self.alert_risk_filter
            .currentText()
        )

        ip_text = (
            self.alert_ip_filter
            .text()
            .strip()
        )

        filtered_alerts = []

        for alert in self.alerts:
            if (
                alert_type != "ALL"
                and alert.get(
                    "type"
                )
                != alert_type
            ):
                continue

            if (
                risk_level != "ALL"
                and self.get_alert_level(
                    alert
                )
                != risk_level
            ):
                continue

            if ip_text:
                source_ip = str(
                    alert.get(
                        "source_ip",
                        "",
                    )
                    or ""
                )

                destination_ip = str(
                    alert.get(
                        "destination_ip",
                        "",
                    )
                    or ""
                )

                if (
                    ip_text
                    not in source_ip
                    and ip_text
                    not in destination_ip
                ):
                    continue

            filtered_alerts.append(
                alert
            )

        self.update_alert_table(
            filtered_alerts
        )

        self.statusBar().showMessage(
            f"Alarm filtresi sonucu: "
            f"{len(filtered_alerts)} alarm"
        )

    def clear_alert_filter(
        self,
    ):
        self.alert_type_filter.setCurrentText(
            "ALL"
        )
        self.alert_risk_filter.setCurrentText(
            "ALL"
        )
        self.alert_ip_filter.clear()

        self.update_alert_table(
            self.alerts
        )

        self.statusBar().showMessage(
            "Alarm filtreleri temizlendi."
        )

    def show_alert_detail(
        self,
        row,
        column,
    ):
        if row >= len(
            self.displayed_alerts
        ):
            return

        alert = (
            self.displayed_alerts[
                row
            ]
        )

        evidence = (
            alert.get(
                "evidence"
            )
            or []
        )

        evidence_text = "\n".join(
            f"- {item}"
            for item in evidence
        )

        if not evidence_text:
            evidence_text = (
                "- Ek evidence bilgisi bulunmuyor."
            )

        detail_text = (
            f"Alert Type: {alert.get('type')}\n"
            f"Level: {self.get_alert_level(alert)}\n"
            f"Severity: {alert.get('severity')}\n"
            f"Risk Score: {alert.get('risk_score')}\n"
            f"Confidence: {alert.get('confidence')}\n"
            f"Source IP: {alert.get('source_ip')}\n"
            f"Destination IP: {alert.get('destination_ip')}\n"
            f"Source Port: {alert.get('source_port')}\n"
            f"Destination Port: {alert.get('destination_port')}\n"
            f"First Seen: {alert.get('first_seen')}\n"
            f"Last Seen: {alert.get('last_seen')}\n"
            f"Packet Count: {alert.get('packet_count')}\n\n"
            f"Reason:\n{alert.get('reason')}\n\n"
            f"Evidence:\n{evidence_text}"
        )

        self.alert_detail.setPlainText(
            detail_text
        )

    # =========================================================
    # REPORT EXPORT
    # =========================================================

    def export_report(
        self,
    ):
        if (
            not self.current_statistics
            or not self.selected_file
        ):
            QMessageBox.warning(
                self,
                "Rapor Oluşturulamadı",
                "Önce bir PCAP analizi tamamlanmalıdır.",
            )
            return

        report_format = (
            self.report_format_combo
            .currentText()
            .upper()
        )

        extension_map = {
            "JSON": "json",
            "HTML": "html",
            "PDF": "pdf",
        }

        extension = (
            extension_map[
                report_format
            ]
        )

        default_name = (
            f"{Path(self.selected_file).stem}"
            f"_ids_report.{extension}"
        )

        filter_map = {
            "JSON": (
                "JSON Files (*.json)"
            ),
            "HTML": (
                "HTML Files (*.html)"
            ),
            "PDF": (
                "PDF Files (*.pdf)"
            ),
        }

        output_path, _ = (
            QFileDialog.getSaveFileName(
                self,
                "IDS Raporunu Kaydet",
                default_name,
                filter_map[
                    report_format
                ],
            )
        )

        if not output_path:
            return

        if not output_path.lower().endswith(
            f".{extension}"
        ):
            output_path += (
                f".{extension}"
            )

        report_data = build_report_data(
            file_path=(
                self.selected_file
            ),
            packets=self.packets,
            statistics=(
                self.current_statistics
            ),
            alerts=self.alerts,
            risk_score=(
                self.current_risk_score
            ),
            risk_level=(
                self.current_risk_level
            ),
            risk_breakdown=(
                self.current_risk_breakdown
            ),
            flows=self.flows,
        )

        try:
            if report_format == "JSON":
                export_json(
                    output_path,
                    report_data,
                )

            elif report_format == "HTML":
                export_html(
                    output_path,
                    report_data,
                )

            elif report_format == "PDF":
                export_pdf(
                    output_path,
                    report_data,
                )

        except Exception as error:
            QMessageBox.critical(
                self,
                "Rapor Hatası",
                (
                    "Rapor oluşturulamadı.\n\n"
                    f"Detay: {error}"
                ),
            )
            return

        QMessageBox.information(
            self,
            "Rapor Oluşturuldu",
            (
                f"{report_format} raporu "
                "başarıyla oluşturuldu.\n\n"
                f"{output_path}"
            ),
        )

        self.statusBar().showMessage(
            f"{report_format} raporu oluşturuldu."
        )

    # =========================================================
    # PENCERE KAPATMA
    # =========================================================

    def closeEvent(
        self,
        event,
    ):
        if (
            self.analysis_thread is not None
            and self.analysis_thread.isRunning()
        ):
            QMessageBox.warning(
                self,
                "Analiz Devam Ediyor",
                (
                    "PCAP analizi hâlâ devam ediyor.\n"
                    "Thread güvenliği için analiz "
                    "tamamlandıktan sonra uygulamayı kapatın."
                ),
            )
            event.ignore()
            return

        event.accept()
