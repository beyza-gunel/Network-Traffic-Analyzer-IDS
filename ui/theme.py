APP_STYLESHEET = """
QMainWindow,
QWidget {
    background-color: #08111f;
    color: #e5edf7;
    font-family: "Segoe UI";
    font-size: 13px;
}

QLabel {
    background-color: transparent;
}

QFrame#sidebar {
    background-color: #0c1728;
    border-right: 1px solid #1e2d43;
}

QLabel#brandMark {
    background-color: #0ea5e9;
    color: #ffffff;
    border-radius: 12px;
    font-size: 21px;
    font-weight: 800;
    padding: 8px;
}

QLabel#brandTitle {
    color: #f8fafc;
    font-size: 17px;
    font-weight: 800;
}

QLabel#brandSubtitle,
QLabel#mutedLabel,
QLabel#cardHint,
QLabel#headerSubtitle {
    color: #8190a5;
}

QLabel#sidebarSection {
    color: #5f718a;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}

QLabel#sidebarModule {
    color: #b8c5d6;
    padding: 5px 2px;
}

QLabel#engineBadge {
    background-color: #102d2a;
    color: #4ade80;
    border: 1px solid #1d5948;
    border-radius: 8px;
    padding: 7px 9px;
    font-weight: 700;
}

QLabel#sidebarMetricTitle {
    color: #6f8097;
    font-size: 10px;
}

QLabel#sidebarMetricValue {
    color: #dce7f4;
    font-size: 14px;
    font-weight: 700;
}

QFrame#headerPanel,
QFrame#actionPanel,
QFrame#sectionPanel,
QFrame#detailPanel {
    background-color: #0d192b;
    border: 1px solid #1d2c42;
    border-radius: 12px;
}

QLabel#headerTitle {
    color: #f8fafc;
    font-size: 23px;
    font-weight: 800;
}

QLabel#sectionTitle {
    color: #f1f5f9;
    font-size: 14px;
    font-weight: 700;
}

QLabel#sectionSubtitle {
    color: #708299;
    font-size: 11px;
}

QLabel#filePathLabel {
    background-color: #091421;
    color: #a9bad0;
    border: 1px solid #1b2c42;
    border-radius: 8px;
    padding: 8px 10px;
}

QPushButton {
    background-color: #142238;
    color: #dce7f4;
    border: 1px solid #263a55;
    border-radius: 8px;
    padding: 8px 12px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #1a2c46;
    border-color: #3a5271;
}

QPushButton:pressed {
    background-color: #0f1d30;
}

QPushButton:disabled {
    background-color: #111b2a;
    color: #53657d;
    border-color: #1b293b;
}

QPushButton#primaryButton {
    background-color: #0ea5e9;
    color: #ffffff;
    border: 1px solid #38bdf8;
    font-weight: 800;
}

QPushButton#primaryButton:hover {
    background-color: #0284c7;
}

QPushButton#dangerButton {
    background-color: #3a1720;
    color: #fca5a5;
    border-color: #6b2634;
}

QFrame#statCard {
    background-color: #0e1b2e;
    border: 1px solid #22334a;
    border-radius: 12px;
}

QLabel#statTitle {
    color: #8395ab;
    font-size: 11px;
    font-weight: 600;
}

QLabel#statValue {
    color: #f8fafc;
    font-size: 25px;
    font-weight: 800;
}

QLabel#statAccentBlue {
    color: #38bdf8;
    font-size: 16px;
}

QLabel#statAccentPurple {
    color: #a78bfa;
    font-size: 16px;
}

QLabel#statAccentGreen {
    color: #4ade80;
    font-size: 16px;
}

QLabel#statAccentOrange {
    color: #fb923c;
    font-size: 16px;
}

QLabel#statAccentRed {
    color: #f87171;
    font-size: 16px;
}

QTabWidget::pane {
    background-color: #0b1727;
    border: 1px solid #1e2f46;
    border-radius: 10px;
    top: -1px;
}

QTabBar::tab {
    background-color: #0b1626;
    color: #8495aa;
    border: 1px solid #1b2b41;
    border-bottom: none;
    padding: 9px 15px;
    margin-right: 3px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}

QTabBar::tab:selected {
    background-color: #102038;
    color: #eaf5ff;
    border-color: #2c4868;
}

QTabBar::tab:hover {
    color: #ffffff;
    background-color: #102038;
}

QLineEdit,
QComboBox,
QDateTimeEdit,
QTextEdit {
    background-color: #091421;
    color: #dce7f4;
    border: 1px solid #21344c;
    border-radius: 7px;
    padding: 7px;
    selection-background-color: #0ea5e9;
}

QLineEdit:focus,
QComboBox:focus,
QDateTimeEdit:focus,
QTextEdit:focus {
    border-color: #38bdf8;
}

QComboBox QAbstractItemView {
    background-color: #0c1728;
    color: #dce7f4;
    border: 1px solid #263a55;
    selection-background-color: #123554;
}

QCheckBox {
    color: #aebdd0;
    spacing: 7px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #38506e;
    background: #0a1524;
    border-radius: 4px;
}

QCheckBox::indicator:checked {
    background: #0ea5e9;
    border-color: #38bdf8;
}

QTableWidget {
    background-color: #0a1524;
    alternate-background-color: #0d1a2c;
    color: #dce7f4;
    gridline-color: #1b2b40;
    border: 1px solid #1f3047;
    border-radius: 8px;
    selection-background-color: #12395a;
    selection-color: #ffffff;
}

QTableWidget::item {
    padding: 6px;
}

QHeaderView::section {
    background-color: #132239;
    color: #c7d5e6;
    border: none;
    border-right: 1px solid #26384f;
    border-bottom: 1px solid #26384f;
    padding: 8px 6px;
    font-weight: 700;
}

QGroupBox {
    background-color: transparent;
    color: #91a3b8;
    border: 1px solid #1d2e45;
    border-radius: 9px;
    margin-top: 10px;
    padding-top: 8px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #8da0b7;
}

QScrollBar:vertical {
    background: #08121f;
    width: 11px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background: #29405b;
    min-height: 30px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #3b5c80;
}

QScrollBar:horizontal {
    background: #08121f;
    height: 10px;
}

QScrollBar::handle:horizontal {
    background: #29405b;
    min-width: 30px;
    border-radius: 5px;
}

QStatusBar {
    background-color: #07101c;
    color: #8194aa;
    border-top: 1px solid #1b2b40;
}

QToolTip {
    background-color: #102038;
    color: #e8f2ff;
    border: 1px solid #31506f;
    padding: 5px;
}
"""


def risk_color(level):
    colors = {
        "LOW": "#4ade80",
        "MEDIUM": "#facc15",
        "HIGH": "#fb923c",
        "CRITICAL": "#f87171",
    }

    return colors.get(
        str(level).upper(),
        "#e5edf7",
    )
