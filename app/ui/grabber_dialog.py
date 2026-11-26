"""
OmniFetch Batch Clipboard Grabber Dialog
Displays links detected from clipboard with Stage 1 CyberShield security indicators.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox
)
from PySide6.QtCore import Qt

from .theme import DARK_COLORS
from ..core.security_gate import SecurityGate

class BatchGrabberDialog(QDialog):
    def __init__(self, detected_links: list[dict], security_gate: SecurityGate = None, parent=None):
        super().__init__(parent)
        self.detected_links = detected_links
        self.security_gate = security_gate
        self.selected_links = []
        self.setWindowTitle("Clipboard Link Grabber")
        self.resize(720, 380)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        header = QLabel(f"Detected {len(self.detected_links)} downloadable link(s) in clipboard:")
        header.setStyleSheet("font-weight: bold; font-size: 13px;")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["", "Type", "Link / Target", "Security Gate"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)

        self.table.setRowCount(len(self.detected_links))

        self.checkboxes = []
        for row, item in enumerate(self.detected_links):
            chk = QCheckBox()
            chk.setChecked(True)
            self.checkboxes.append(chk)
            self.table.setCellWidget(row, 0, chk)

            # Type
            type_item = QTableWidgetItem(item.get("engine_type", "HTTP"))
            self.table.setItem(row, 1, type_item)

            # Link name / url
            url_text = item.get("filename", item.get("url", ""))
            target_item = QTableWidgetItem(url_text)
            target_item.setToolTip(item.get("url", ""))
            self.table.setItem(row, 2, target_item)

            # Stage 1 Security Gate Evaluation
            sec_badge = "Clean"
            sec_color = Qt.green
            if self.security_gate:
                eval_res = self.security_gate.evaluate_pre_download(item.get("url", ""), item.get("filename", ""))
                sev = eval_res.get("severity", "CLEAN")
                if sev == "CRITICAL":
                    sec_badge = "Critical Trap"
                    sec_color = Qt.red
                    chk.setChecked(False)  # Auto-uncheck traps
                elif sev == "LOW":
                    sec_badge = "Review"
                    sec_color = Qt.yellow

            sec_item = QTableWidgetItem(sec_badge)
            sec_item.setForeground(sec_color)
            self.table.setItem(row, 3, sec_item)

        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.btn_select_all = QPushButton("Select All")
        self.btn_select_all.clicked.connect(self._select_all)
        self.btn_deselect_all = QPushButton("Deselect All")
        self.btn_deselect_all.clicked.connect(self._deselect_all)

        btn_row.addWidget(self.btn_select_all)
        btn_row.addWidget(self.btn_deselect_all)
        btn_row.addStretch()

        self.btn_download_sel = QPushButton("Download Selected")
        self.btn_download_sel.clicked.connect(self._download_selected)
        self.btn_download_all = QPushButton("Download All")
        self.btn_download_all.clicked.connect(self._download_all)
        self.btn_dismiss = QPushButton("Dismiss")
        self.btn_dismiss.clicked.connect(self.reject)

        btn_row.addWidget(self.btn_dismiss)
        btn_row.addWidget(self.btn_download_sel)
        btn_row.addWidget(self.btn_download_all)
        layout.addLayout(btn_row)

    def _select_all(self):
        for chk in self.checkboxes:
            chk.setChecked(True)

    def _deselect_all(self):
        for chk in self.checkboxes:
            chk.setChecked(False)

    def _download_selected(self):
        self.selected_links = [
            self.detected_links[i] for i, chk in enumerate(self.checkboxes) if chk.isChecked()
        ]
        self.accept()

    def _download_all(self):
        self.selected_links = list(self.detected_links)
        self.accept()
