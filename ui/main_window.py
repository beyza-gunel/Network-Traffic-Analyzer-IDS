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
    QDateEdit,
    QTimeEdit,
    QCheckBox,
    QFrame,
    QSizePolicy,
    QSplitter,
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
from ui.theme import (
    APP_STYLESHEET,
    risk_color,
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
        self.resize(1360, 800)
        self.setMinimumSize(
            1080,
            640,
        )
        self.setStyleSheet(
            APP_STYLESHEET
        )

        self.create_ui()

    # =========================================================
    # UI
    # =========================================================

    def create_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(
            central_widget
        )

        root_layout = QHBoxLayout(
            central_widget
        )
        root_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )
        root_layout.setSpacing(
            0
        )

        # -----------------------------------------------------
        # Sol bilgi paneli
        # -----------------------------------------------------

        sidebar = self.create_sidebar()
        root_layout.addWidget(
            sidebar
        )

        # -----------------------------------------------------
        # Ana içerik
        # -----------------------------------------------------

        content_widget = QWidget()
        content_layout = QVBoxLayout(
            content_widget
        )
        content_layout.setContentsMargins(
            12,
            10,
            12,
            8,
        )
        content_layout.setSpacing(
            8
        )

        root_layout.addWidget(
            content_widget,
            1,
        )

        header_panel = QFrame()
        header_panel.setObjectName(
            "headerPanel"
        )
        header_panel.setFixedHeight(
            82
        )

        header_layout = QHBoxLayout(
            header_panel
        )
        header_layout.setContentsMargins(
            16,
            10,
            16,
            10,
        )

        header_text = QVBoxLayout()
        header_text.setSpacing(
            2
        )

        title = QLabel(
            "Network Traffic Analyzer & IDS"
        )
        title.setObjectName(
            "headerTitle"
        )

        subtitle = QLabel(
            (
                "PCAP intelligence • multi-layer detection • "
                "risk correlation • flow analytics"
            )
        )
        subtitle.setObjectName(
            "headerSubtitle"
        )

        header_text.addWidget(
            title
        )
        header_text.addWidget(
            subtitle
        )

        header_layout.addLayout(
            header_text,
            1,
        )

        self.header_status_label = QLabel(
            "● ENGINE READY"
        )
        self.header_status_label.setObjectName(
            "engineBadge"
        )

        header_layout.addWidget(
            self.header_status_label
        )

        content_layout.addWidget(
            header_panel
        )

        # -----------------------------------------------------
        # Dosya / analiz / rapor aksiyonları
        # -----------------------------------------------------

        action_panel = QFrame()
        action_panel.setObjectName(
            "actionPanel"
        )
        action_panel.setFixedHeight(
            58
        )

        action_layout = QHBoxLayout(
            action_panel
        )
        action_layout.setContentsMargins(
            12,
            10,
            12,
            10,
        )

        self.select_file_button = QPushButton(
            "PCAP DOSYASI SEÇ"
        )

        self.analyze_button = QPushButton(
            "ANALİZİ BAŞLAT"
        )
        self.analyze_button.setObjectName(
            "primaryButton"
        )

        self.file_label = QLabel(
            "Henüz dosya seçilmedi."
        )
        self.file_label.setObjectName(
            "filePathLabel"
        )
        self.file_label.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Preferred,
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

        action_layout.addWidget(
            self.select_file_button
        )
        action_layout.addWidget(
            self.analyze_button
        )
        action_layout.addWidget(
            self.file_label,
            1,
        )
        action_layout.addWidget(
            self.report_format_combo
        )
        action_layout.addWidget(
            self.export_report_button
        )

        content_layout.addWidget(
            action_panel
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
            content_layout
        )

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(
            True
        )
        content_layout.addWidget(
            self.tabs,
            1,
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

        self.statusBar().showMessage(
            "Engine ready. Select a PCAP/PCAPNG file to begin."
        )

    def create_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName(
            "sidebar"
        )
        sidebar.setFixedWidth(
            205
        )

        layout = QVBoxLayout(
            sidebar
        )
        layout.setContentsMargins(
            14,
            14,
            14,
            14,
        )
        layout.setSpacing(
            7
        )

        brand_row = QHBoxLayout()

        brand_mark = QLabel(
            "N"
        )
        brand_mark.setObjectName(
            "brandMark"
        )
        brand_mark.setFixedSize(
            44,
            44,
        )
        brand_mark.setAlignment(
            Qt.AlignCenter
        )

        brand_text = QVBoxLayout()
        brand_text.setSpacing(
            0
        )

        brand_title = QLabel(
            "NTA / IDS"
        )
        brand_title.setObjectName(
            "brandTitle"
        )

        brand_subtitle = QLabel(
            "Security Console"
        )
        brand_subtitle.setObjectName(
            "brandSubtitle"
        )

        brand_text.addWidget(
            brand_title
        )
        brand_text.addWidget(
            brand_subtitle
        )

        brand_row.addWidget(
            brand_mark
        )
        brand_row.addLayout(
            brand_text,
            1,
        )

        layout.addLayout(
            brand_row
        )

        layout.addSpacing(
            8
        )

        system_title = QLabel(
            "SYSTEM STATUS"
        )
        system_title.setObjectName(
            "sidebarSection"
        )
        layout.addWidget(
            system_title
        )

        self.engine_status_label = QLabel(
            "● ENGINE READY"
        )
        self.engine_status_label.setObjectName(
            "engineBadge"
        )
        layout.addWidget(
            self.engine_status_label
        )

        layout.addSpacing(
            6
        )

        modules_title = QLabel(
            "ANALYSIS MODULES"
        )
        modules_title.setObjectName(
            "sidebarSection"
        )
        layout.addWidget(
            modules_title
        )

        for module in [
            "◦ Packet Parser",
            "◦ Traffic Analyzer",
            "◦ Flow Analyzer",
            "◦ Detection Engine",
            "◦ Risk Correlation",
            "◦ Wireless IDS",
        ]:
            label = QLabel(
                module
            )
            label.setObjectName(
                "sidebarModule"
            )
            layout.addWidget(
                label
            )

        layout.addSpacing(
            6
        )

        live_title = QLabel(
            "CURRENT ANALYSIS"
        )
        live_title.setObjectName(
            "sidebarSection"
        )
        layout.addWidget(
            live_title
        )

        self.sidebar_file_value = self.create_sidebar_metric(
            layout,
            "CAPTURE",
            "No file selected",
        )

        self.sidebar_packet_value = self.create_sidebar_metric(
            layout,
            "PACKETS",
            "0",
        )

        self.sidebar_alert_value = self.create_sidebar_metric(
            layout,
            "ALERTS",
            "0",
        )

        self.sidebar_risk_value = self.create_sidebar_metric(
            layout,
            "RISK",
            "LOW",
        )

        layout.addStretch(
            1
        )

        footer = QLabel(
            (
                "Offline PCAP Analysis\n"
                "Network + Wireless Detection"
            )
        )
        footer.setObjectName(
            "mutedLabel"
        )
        footer.setWordWrap(
            True
        )
        layout.addWidget(
            footer
        )

        return sidebar

    def create_sidebar_metric(
        self,
        layout,
        title,
        value,
    ):
        title_label = QLabel(
            title
        )
        title_label.setObjectName(
            "sidebarMetricTitle"
        )

        value_label = QLabel(
            value
        )
        value_label.setObjectName(
            "sidebarMetricValue"
        )
        value_label.setWordWrap(
            True
        )

        layout.addWidget(
            title_label
        )
        layout.addWidget(
            value_label
        )

        return value_label

    # =========================================================
    # DASHBOARD
    # =========================================================

    def create_statistics_area(
        self,
        main_layout,
    ):
        section = QFrame()
        section.setObjectName(
            "sectionPanel"
        )
        section.setFixedHeight(
            210
        )

        section_layout = QVBoxLayout(
            section
        )
        section_layout.setContentsMargins(
            10,
            8,
            10,
            8,
        )
        section_layout.setSpacing(
            4
        )

        section_title = QLabel(
            "Security Overview"
        )
        section_title.setObjectName(
            "sectionTitle"
        )

        section_subtitle = QLabel(
            (
                "Live summary of traffic volume, endpoints, "
                "connections and detected security events."
            )
        )
        section_subtitle.setObjectName(
            "sectionSubtitle"
        )

        section_layout.addWidget(
            section_title
        )
        section_layout.addWidget(
            section_subtitle
        )

        cards_layout = QGridLayout()
        cards_layout.setHorizontalSpacing(
            9
        )
        cards_layout.setVerticalSpacing(
            9
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
                "◉",
                "statAccentBlue",
                "Captured frames",
                0,
                0,
            ),
            (
                "Unique IPs",
                self.unique_ips_label,
                "◆",
                "statAccentPurple",
                "Observed endpoints",
                0,
                1,
            ),
            (
                "Unique Ports",
                self.unique_ports_label,
                "◇",
                "statAccentBlue",
                "Observed ports",
                0,
                2,
            ),
            (
                "TCP Connections",
                self.tcp_connections_label,
                "⇄",
                "statAccentGreen",
                "Bidirectional sessions",
                0,
                3,
            ),
            (
                "UDP Traffic",
                self.udp_packets_label,
                "◌",
                "statAccentPurple",
                "UDP packets",
                1,
                0,
            ),
            (
                "Critical Alerts",
                self.critical_alerts_label,
                "!",
                "statAccentRed",
                "Critical detections",
                1,
                1,
            ),
            (
                "Suspicious Traffic",
                self.suspicious_label,
                "⚠",
                "statAccentOrange",
                "Generated alerts",
                1,
                2,
            ),
            (
                "Risk Level",
                self.risk_label,
                "⬢",
                "statAccentGreen",
                "Correlated posture",
                1,
                3,
            ),
        ]

        for (
            title,
            label,
            icon,
            accent,
            hint,
            row,
            column,
        ) in cards:
            cards_layout.addWidget(
                self.create_stat_card(
                    title,
                    label,
                    icon,
                    accent,
                    hint,
                ),
                row,
                column,
            )

        section_layout.addLayout(
            cards_layout
        )

        main_layout.addWidget(
            section
        )

    def create_stat_card(
        self,
        title,
        value_label,
        icon,
        accent_name,
        hint,
    ):
        card = QFrame()
        card.setObjectName(
            "statCard"
        )
        card.setFixedHeight(
            74
        )

        layout = QVBoxLayout(
            card
        )
        layout.setContentsMargins(
            10,
            6,
            10,
            6,
        )
        layout.setSpacing(
            1
        )

        top = QHBoxLayout()

        icon_label = QLabel(
            icon
        )
        icon_label.setObjectName(
            accent_name
        )

        title_label = QLabel(
            title
        )
        title_label.setObjectName(
            "statTitle"
        )

        top.addWidget(
            icon_label
        )
        top.addWidget(
            title_label
        )
        top.addStretch(
            1
        )

        value_label.setObjectName(
            "statValue"
        )

        hint_label = QLabel(
            hint
        )
        hint_label.setObjectName(
            "cardHint"
        )

        layout.addLayout(
            top
        )
        layout.addWidget(
            value_label
        )
        layout.addWidget(
            hint_label
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
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setSpacing(
            6
        )

        filter_panel = QFrame()
        filter_panel.setObjectName(
            "detailPanel"
        )
        filter_panel_layout = QVBoxLayout(
            filter_panel
        )
        filter_panel_layout.setContentsMargins(
            10,
            9,
            10,
            9,
        )
        filter_panel_layout.setSpacing(
            7
        )

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
                "802.11",
                "EAPOL",
                "HTTP",
                "HTTPS",
                "DNS",
                "OTHER",
            ]
        )

        self.filter_button = QPushButton(
            "FİLTRELE"
        )
        self.filter_button.setObjectName(
            "primaryButton"
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

        filter_panel_layout.addLayout(
            filter_layout
        )

        time_filter_layout = QHBoxLayout()

        self.time_filter_check = QCheckBox(
            "Tarih/Saat filtresi"
        )

        self.start_date_edit = QDateEdit()
        self.start_date_edit.setDisplayFormat(
            "yyyy-MM-dd"
        )
        self.start_date_edit.setCalendarPopup(
            True
        )
        self.start_date_edit.setEnabled(
            False
        )

        self.start_clock_edit = QTimeEdit()
        self.start_clock_edit.setDisplayFormat(
            "HH:mm:ss"
        )
        self.start_clock_edit.setEnabled(
            False
        )

        self.end_date_edit = QDateEdit()
        self.end_date_edit.setDisplayFormat(
            "yyyy-MM-dd"
        )
        self.end_date_edit.setCalendarPopup(
            True
        )
        self.end_date_edit.setEnabled(
            False
        )

        self.end_clock_edit = QTimeEdit()
        self.end_clock_edit.setDisplayFormat(
            "HH:mm:ss"
        )
        self.end_clock_edit.setEnabled(
            False
        )

        time_filter_layout.addWidget(
            self.time_filter_check
        )

        time_filter_layout.addWidget(
            QLabel(
                "Başlangıç Tarihi"
            )
        )
        time_filter_layout.addWidget(
            self.start_date_edit
        )

        time_filter_layout.addWidget(
            QLabel(
                "Saat"
            )
        )
        time_filter_layout.addWidget(
            self.start_clock_edit
        )

        time_filter_layout.addWidget(
            QLabel(
                "Bitiş Tarihi"
            )
        )
        time_filter_layout.addWidget(
            self.end_date_edit
        )

        time_filter_layout.addWidget(
            QLabel(
                "Saat"
            )
        )
        time_filter_layout.addWidget(
            self.end_clock_edit
        )

        time_filter_layout.addStretch(
            1
        )

        filter_panel_layout.addLayout(
            time_filter_layout
        )

        layout.addWidget(
            filter_panel
        )

        self.time_filter_check.toggled.connect(
            self.start_date_edit.setEnabled
        )
        self.time_filter_check.toggled.connect(
            self.start_clock_edit.setEnabled
        )
        self.time_filter_check.toggled.connect(
            self.end_date_edit.setEnabled
        )
        self.time_filter_check.toggled.connect(
            self.end_clock_edit.setEnabled
        )

        self.packet_table = QTableWidget()

        columns = [
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Application / Frame",
            "Source Port",
            "Destination Port",
            "Packet Size",
            "TCP Flags",
            "DNS Query",
            "Source MAC",
            "BSSID",
        ]

        self.packet_table.setColumnCount(
            len(
                columns
            )
        )
        self.packet_table.setHorizontalHeaderLabels(
            columns
        )
        self.packet_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents
        )
        self.packet_table.horizontalHeader().setStretchLastSection(
            True
        )
        self.packet_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.packet_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.packet_table.setAlternatingRowColors(
            True
        )

        self.packet_splitter = QSplitter(
            Qt.Vertical
        )

        self.packet_splitter.addWidget(
            self.packet_table
        )

        self.packet_detail = QTextEdit()
        self.packet_detail.setReadOnly(
            True
        )
        self.packet_detail.setPlaceholderText(
            (
                "Bir paket seçerek Layer 2 / Layer 3 / "
                "transport / application detaylarını görüntüleyin."
            )
        )

        self.packet_splitter.addWidget(
            self.packet_detail
        )

        self.packet_splitter.setStretchFactor(
            0,
            4
        )
        self.packet_splitter.setStretchFactor(
            1,
            2
        )
        self.packet_splitter.setSizes(
            [
                360,
                150,
            ]
        )

        layout.addWidget(
            self.packet_splitter,
            1
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
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setSpacing(
            6
        )

        filter_panel = QFrame()
        filter_panel.setObjectName(
            "detailPanel"
        )

        alert_filter_layout = QHBoxLayout(
            filter_panel
        )
        alert_filter_layout.setContentsMargins(
            10,
            9,
            10,
            9,
        )

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
            "IP / MAC / BSSID / SSID"
        )

        self.alert_filter_button = QPushButton(
            "ALARM FİLTRELE"
        )
        self.alert_filter_button.setObjectName(
            "primaryButton"
        )

        self.alert_clear_filter_button = QPushButton(
            "TEMİZLE"
        )

        alert_filter_layout.addWidget(
            QLabel(
                "Alert Type"
            )
        )
        alert_filter_layout.addWidget(
            self.alert_type_filter
        )
        alert_filter_layout.addWidget(
            QLabel(
                "Risk"
            )
        )
        alert_filter_layout.addWidget(
            self.alert_risk_filter
        )
        alert_filter_layout.addWidget(
            self.alert_ip_filter,
            1,
        )
        alert_filter_layout.addWidget(
            self.alert_filter_button
        )
        alert_filter_layout.addWidget(
            self.alert_clear_filter_button
        )

        layout.addWidget(
            filter_panel
        )

        self.alert_table = QTableWidget()

        columns = [
            "Alert Type",
            "Level",
            "Source Entity",
            "Destination Entity",
            "Risk",
            "Confidence",
            "Packets",
            "Context",
            "Reason",
        ]

        self.alert_table.setColumnCount(
            len(
                columns
            )
        )
        self.alert_table.setHorizontalHeaderLabels(
            columns
        )
        self.alert_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents
        )
        self.alert_table.horizontalHeader().setStretchLastSection(
            True
        )
        self.alert_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )
        self.alert_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )
        self.alert_table.setAlternatingRowColors(
            True
        )

        self.alert_splitter = QSplitter(
            Qt.Vertical
        )

        self.alert_splitter.addWidget(
            self.alert_table
        )

        self.alert_detail = QTextEdit()
        self.alert_detail.setReadOnly(
            True
        )
        self.alert_detail.setPlaceholderText(
            (
                "Bir alarm seçerek risk, confidence, zaman, "
                "kaynak/hedef ve evidence detayını görüntüleyin."
            )
        )

        self.alert_splitter.addWidget(
            self.alert_detail
        )

        self.alert_splitter.setStretchFactor(
            0,
            4
        )
        self.alert_splitter.setStretchFactor(
            1,
            2
        )
        self.alert_splitter.setSizes(
            [
                360,
                150,
            ]
        )

        layout.addWidget(
            self.alert_splitter,
            1
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

            self.sidebar_file_value.setText(
                validation.path.name
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

        self.engine_status_label.setText(
            "● ANALYZING"
        )
        self.header_status_label.setText(
            "● ANALYZING"
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

        self.header_status_label.setText(
            "● ANALYZING"
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

        self.engine_status_label.setText(
            "● ANALYSIS COMPLETE"
        )
        self.header_status_label.setText(
            "● ANALYSIS COMPLETE"
        )
        self.sidebar_packet_value.setText(
            str(
                result.total_packets
            )
        )
        self.sidebar_alert_value.setText(
            str(
                len(
                    self.alerts
                )
            )
        )
        self.sidebar_risk_value.setText(
            str(
                result.risk_level
            )
        )
        self.sidebar_risk_value.setStyleSheet(
            f"color: {risk_color(result.risk_level)};"
            "font-size: 14px;"
            "font-weight: 800;"
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

        self.engine_status_label.setText(
            "● ANALYSIS FAILED"
        )
        self.header_status_label.setText(
            "● ANALYSIS FAILED"
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

        color = risk_color(
            risk_level
        )

        self.risk_label.setStyleSheet(
            f"color: {color};"
            "font-size: 25px;"
            "font-weight: 800;"
        )

    # =========================================================
    # PACKET TABLOSU / DETAY
    # =========================================================

    @staticmethod
    def format_packet_timestamp(
        timestamp,
    ):
        if timestamp is None:
            return ""

        try:
            milliseconds = int(
                float(
                    timestamp
                )
                * 1000
            )

            return (
                QDateTime
                .fromMSecsSinceEpoch(
                    milliseconds
                )
                .toString(
                    "yyyy-MM-dd HH:mm:ss.zzz"
                )
            )

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            return str(
                timestamp
            )

    def get_packet_application_label(
        self,
        packet,
    ):
        application = packet.get(
            "application_protocol"
        )

        if application:
            return str(
                application
            )

        wlan_frame = packet.get(
            "wlan_frame_name"
        )

        if wlan_frame:
            return str(
                wlan_frame
            )

        return ""

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
                    self.format_packet_timestamp(
                        packet.get(
                            "timestamp"
                        )
                    ),
                    packet.get(
                        "src_ip"
                    ),
                    packet.get(
                        "dst_ip"
                    ),
                    packet.get(
                        "protocol"
                    ),
                    self.get_packet_application_label(
                        packet
                    ),
                    packet.get(
                        "src_port"
                    ),
                    packet.get(
                        "dst_port"
                    ),
                    packet.get(
                        "packet_size"
                    ),
                    packet.get(
                        "tcp_flags"
                    ),
                    packet.get(
                        "dns_query"
                    ),
                    packet.get(
                        "src_mac"
                    ),
                    packet.get(
                        "bssid"
                    ),
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
            f"Timestamp: "
            f"{self.format_packet_timestamp(packet.get('timestamp'))}\n"
            f"Raw Timestamp: {packet.get('timestamp')}\n"
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
            f"WLAN Category: "
            f"{packet.get('wlan_frame_category')}\n"
            f"WLAN Frame: "
            f"{packet.get('wlan_frame_name')}\n"
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

        minimum_datetime = (
            QDateTime.fromSecsSinceEpoch(
                minimum
            )
        )

        maximum_datetime = (
            QDateTime.fromSecsSinceEpoch(
                maximum
            )
        )

        self.start_date_edit.setDate(
            minimum_datetime.date()
        )
        self.start_clock_edit.setTime(
            minimum_datetime.time()
        )

        self.end_date_edit.setDate(
            maximum_datetime.date()
        )
        self.end_clock_edit.setTime(
            maximum_datetime.time()
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

        start_datetime = QDateTime(
            self.start_date_edit.date(),
            self.start_clock_edit.time(),
        )

        end_datetime = QDateTime(
            self.end_date_edit.date(),
            self.end_clock_edit.time(),
        )

        start_timestamp = (
            start_datetime
            .toSecsSinceEpoch()
        )

        end_timestamp = (
            end_datetime
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
            ).upper()

            application_protocol = str(
                packet.get(
                    "application_protocol",
                    "",
                )
                or ""
            ).upper()

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

            if protocol_text != "ALL":
                if protocol_text in {
                    "HTTP",
                    "HTTPS",
                    "DNS",
                    "EAPOL",
                }:
                    if (
                        application_protocol
                        != protocol_text
                    ):
                        continue
                elif (
                    protocol
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

    def get_alert_entity(
        self,
        alert,
        destination=False,
    ):
        ip_key = (
            "destination_ip"
            if destination
            else "source_ip"
        )

        ip_value = alert.get(
            ip_key
        )

        if ip_value:
            return str(
                ip_value
            )

        evidence = (
            alert.get(
                "evidence"
            )
            or []
        )

        if destination:
            prefixes = [
                "Destination MAC:",
                "MAC 2:",
                "Client MAC:",
                "Target MAC:",
            ]
        else:
            prefixes = [
                "Source MAC:",
                "MAC 1:",
                "AP MAC:",
                "Attacker MAC:",
                "BSSID:",
            ]

        for prefix in prefixes:
            for item in evidence:
                text = str(
                    item
                )

                if text.lower().startswith(
                    prefix.lower()
                ):
                    return (
                        text.split(
                            ":",
                            1,
                        )[1]
                        .strip()
                    )

        return "-"

    def get_alert_context(
        self,
        alert,
    ):
        evidence = (
            alert.get(
                "evidence"
            )
            or []
        )

        context_items = []

        for item in evidence:
            text = str(
                item
            )

            if (
                "ssid" in text.lower()
                or "bssid"
                in text.lower()
                or "channel"
                in text.lower()
            ):
                context_items.append(
                    text
                )

        if not context_items:
            return "-"

        return " | ".join(
            context_items[:2]
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
            confidence = alert.get(
                "confidence"
            )

            if confidence is None:
                confidence_text = "-"
            else:
                try:
                    confidence_text = (
                        f"{float(confidence) * 100:.0f}%"
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    confidence_text = str(
                        confidence
                    )

            values = [
                alert.get(
                    "type"
                ),
                self.get_alert_level(
                    alert
                ),
                self.get_alert_entity(
                    alert,
                    destination=False,
                ),
                self.get_alert_entity(
                    alert,
                    destination=True,
                ),
                alert.get(
                    "risk_score"
                ),
                confidence_text,
                alert.get(
                    "packet_count"
                ),
                self.get_alert_context(
                    alert
                ),
                alert.get(
                    "reason"
                ),
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

                if (
                    column == 1
                    and str(
                        value
                    ).upper()
                    == "CRITICAL"
                ):
                    item.setForeground(
                        "#f87171"
                    )

                self.alert_table.setItem(
                    row,
                    column,
                    item,
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
                searchable = " ".join(
                    [
                        str(
                            alert.get(
                                "source_ip",
                                "",
                            )
                            or ""
                        ),
                        str(
                            alert.get(
                                "destination_ip",
                                "",
                            )
                            or ""
                        ),
                        " ".join(
                            str(
                                item
                            )
                            for item
                            in (
                                alert.get(
                                    "evidence"
                                )
                                or []
                            )
                        ),
                    ]
                ).lower()

                if (
                    ip_text.lower()
                    not in searchable
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
            f"Source Entity: {self.get_alert_entity(alert, False)}\n"
            f"Destination Entity: {self.get_alert_entity(alert, True)}\n"
            f"Context: {self.get_alert_context(alert)}\n"
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
