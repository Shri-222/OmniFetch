"""
OmniFetch Dark Theme (Linear & Fluent Inspired Palette)
Clean, professional desktop aesthetic with high-contrast text and crisp accents.
"""

DARK_COLORS = {
    "bg_main": "#0d0f17",
    "bg_card": "#121520",
    "bg_subtle": "#161b26",
    "border": "#1f2433",
    "border_focus": "#00d2ff",
    "text_main": "#e5e7eb",
    "text_muted": "#9ca3af",
    "accent": "#0070f3",
    "accent_hover": "#00d2ff",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#ef4444",
}

DARK_THEME_QSS = """
QMainWindow {
    background-color: #0d0f17;
    color: #e5e7eb;
}

QWidget {
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
    color: #e5e7eb;
}

/* Sidebar Navigation */
QWidget#sidebarContainer {
    background-color: #121520;
    border-right: 1px solid #1f2433;
}

QListWidget#sidebar {
    background-color: transparent;
    border: none;
    padding-top: 12px;
    outline: none;
}

QListWidget#sidebar::item {
    height: 40px;
    padding-left: 16px;
    margin: 2px 8px;
    border-radius: 6px;
    color: #9ca3af;
    font-weight: 500;
}

QListWidget#sidebar::item:hover {
    background-color: #1a1f2e;
    color: #f3f4f6;
}

QListWidget#sidebar::item:selected {
    background-color: #22293d;
    color: #00d2ff;
    font-weight: 600;
}

QFrame#sidebarDivider {
    color: #1f2433;
    background-color: #1f2433;
    border: none;
    height: 1px;
    max-height: 1px;
    margin: 6px 12px;
}

QPushButton#btnSidebar {
    background-color: #161b26;
    border: 1px solid #232a3d;
    border-radius: 6px;
    padding: 8px 14px;
    color: #e5e7eb;
    font-weight: 500;
    text-align: left;
}

QPushButton#btnSidebar:hover {
    background-color: #22293d;
    border-color: #3b4563;
    color: #00d2ff;
}

QPushButton#btnSidebar:pressed {
    background-color: #181d2b;
}

/* Top Header Bar */
QWidget#headerBar {
    background-color: #121520;
    border-bottom: 1px solid #1f2433;
}

QFrame#headerSeparator {
    color: #1f2433;
    background-color: #1f2433;
    border: none;
    width: 1px;
    max-width: 1px;
    margin: 4px 4px;
}

/* Top Toolbar (Legacy/Fallback) */
QToolBar {
    background-color: #121520;
    border-bottom: 1px solid #1f2433;
    padding: 8px 16px;
    spacing: 8px;
}

QPushButton {
    background-color: #1a1f2e;
    border: 1px solid #2b334a;
    border-radius: 6px;
    padding: 7px 16px;
    color: #f3f4f6;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #242c40;
    border-color: #3b4563;
}

QPushButton:pressed {
    background-color: #181d2b;
}

QPushButton#btnPrimary {
    background-color: #0070f3;
    border: 1px solid #0060df;
    color: #ffffff;
    font-weight: 600;
}

QPushButton#btnPrimary:hover {
    background-color: #0060df;
}

QPushButton#btnAccent {
    background-color: #00d2ff;
    border: 1px solid #00b4db;
    color: #0d0f17;
    font-weight: 600;
}

QPushButton#btnAccent:hover {
    background-color: #26dcff;
}

/* Table View */
QTableView {
    background-color: #0d0f17;
    border: none;
    gridline-color: #171c28;
    selection-background-color: #1c2336;
    selection-color: #f3f4f6;
    outline: none;
}

QTableView::item {
    padding: 8px;
    border-bottom: 1px solid #141824;
}

QTableView::item:selected {
    background-color: #1c2336;
}

QHeaderView::section {
    background-color: #121520;
    color: #9ca3af;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #1f2433;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

QHeaderView::section:hover {
    background-color: #1a1f2e;
    color: #e5e7eb;
}

QWidget#filterBar {
    background-color: #10131e;
    border-bottom: 1px solid #1f2433;
}

QPushButton#pillBtn {
    background-color: #161b26;
    border: 1px solid #232a3d;
    border-radius: 12px;
    padding: 4px 12px;
    color: #9ca3af;
    font-size: 12px;
    font-weight: 500;
}

QPushButton#pillBtn:hover {
    background-color: #1f2638;
    color: #f3f4f6;
}

QPushButton#pillBtn[active="true"] {
    background-color: rgba(6, 182, 212, 36);
    border: 1px solid #06b6d4;
    color: #00d2ff;
    font-weight: 600;
}

QLabel#sidebarCatHeader {
    color: #6b7280;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 8px 16px 4px 16px;
}

QSplitter::handle:vertical {
    background-color: #1f2433;
    height: 3px;
}

QSplitter::handle:vertical:hover {
    background-color: #06b6d4;
}

QPushButton#statusPillBtn {
    background-color: #181d2b;
    border: 1px solid #2b334a;
    border-radius: 10px;
    padding: 2px 10px;
    color: #d1d5db;
    font-size: 11px;
    font-weight: 500;
}

QPushButton#statusPillBtn:hover {
    border-color: #06b6d4;
    color: #00d2ff;
}

/* Dialogs & Inputs */
QDialog {
    background-color: #121520;
    color: #e5e7eb;
}

QLineEdit {
    background-color: #0d0f17;
    border: 1px solid #2b334a;
    border-radius: 6px;
    padding: 8px 12px;
    color: #f3f4f6;
    selection-background-color: #0070f3;
}

QLineEdit:focus {
    border: 1px solid #00d2ff;
}

QComboBox {
    background-color: #0d0f17;
    border: 1px solid #2b334a;
    border-radius: 6px;
    padding: 8px 12px;
    color: #f3f4f6;
}

QComboBox QAbstractItemView {
    background-color: #121520;
    border: 1px solid #2b334a;
    color: #f3f4f6;
    selection-background-color: #1c2336;
}

/* Status Bar */
QStatusBar {
    background-color: #121520;
    border-top: 1px solid #1f2433;
    color: #9ca3af;
    font-size: 12px;
    padding: 4px 12px;
}
"""
