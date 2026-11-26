"""
OmniFetch SmartProxy Configuration & Health Tester Dialog
Allows users to configure, test, and manage rotating HTTP/HTTPS proxies with:
- MegaBasterd-style Passive SmartProxy mode toggle.
- Concurrent 'Test Proxy List' button measuring live latency.
- Live results table filtering dead proxies and sorting by speed.
"""

import asyncio
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QCheckBox, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal

from ..engines.mega.proxy_pool import ProxyPool
from .theme import DARK_COLORS
from .icons import get_icon

class ProxyTestThread(QThread):
    finished_signal = Signal(dict)

    def __init__(self, proxy_strings: list[str]):
        super().__init__()
        self.proxy_strings = proxy_strings

    def run(self):
        res = asyncio.run(ProxyPool.test_proxy_list(self.proxy_strings))
        self.finished_signal.emit(res)

class ProxyDialog(QDialog):
    def __init__(self, proxy_pool: ProxyPool, parent=None, config=None):
        super().__init__(parent)
        self.proxy_pool = proxy_pool
        self.config = config
        self.setWindowTitle("SmartProxy Pool & Health Tester")
        self.resize(650, 520)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header info
        info_lbl = QLabel(
            "Configure optional HTTP/HTTPS proxies for MegaBasterd-style failover.\n"
            "By default, Passive Mode downloads directly at 100% full speed with zero proxies,\n"
            "and only activates proxy rotation if MEGA returns HTTP 509 Bandwidth Limit Exceeded."
        )
        info_lbl.setStyleSheet(f"color: {DARK_COLORS['text_muted']}; font-size: 11px;")
        layout.addWidget(info_lbl)

        # Passive mode checkbox
        self.passive_chk = QCheckBox("Passive Mode (Direct download first; rotate proxies only on HTTP 509)")
        self.passive_chk.setChecked(self.proxy_pool.passive_mode)
        layout.addWidget(self.passive_chk)

        # Text edit for proxy list
        lbl_input = QLabel("Proxy List (one per line, e.g. 1.2.3.4:8080 or http://user:pass@1.2.3.4:8080):")
        layout.addWidget(lbl_input)

        self.proxy_edit = QTextEdit()
        existing_proxies = [e.raw for e in self.proxy_pool.entries]
        self.proxy_edit.setPlainText("\n".join(existing_proxies))
        self.proxy_edit.setMaximumHeight(120)
        layout.addWidget(self.proxy_edit)

        # Action row
        btn_row = QHBoxLayout()
        self.btn_test = QPushButton("Test Proxy List")
        self.btn_test.setIcon(get_icon("activity"))
        self.btn_test.clicked.connect(self._run_proxy_test)
        btn_row.addWidget(self.btn_test)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # indeterminate
        btn_row.addWidget(self.progress_bar)

        self.summary_lbl = QLabel("")
        btn_row.addWidget(self.summary_lbl)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Proxy", "Status", "Latency", "Error / Detail"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        layout.addWidget(self.table)

        # Dialog buttons
        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        self.btn_save = QPushButton("Save & Apply")
        self.btn_save.clicked.connect(self._save_and_apply)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)

        bottom_row.addWidget(self.btn_cancel)
        bottom_row.addWidget(self.btn_save)
        layout.addLayout(bottom_row)

    def _run_proxy_test(self):
        text = self.proxy_edit.toPlainText().strip()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            QMessageBox.information(self, "No Proxies", "Please enter at least one proxy to test.")
            return

        self.btn_test.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.summary_lbl.setText("Testing proxies concurrently...")

        self.test_thread = ProxyTestThread(lines)
        self.test_thread.finished_signal.connect(self._on_test_finished)
        self.test_thread.start()

    def _on_test_finished(self, results: dict):
        self.btn_test.setEnabled(True)
        self.progress_bar.setVisible(False)

        alive = results["alive_count"]
        dead = results["dead_count"]
        self.summary_lbl.setText(f"Result: {alive} Alive / {dead} Dead")

        items = results["results"]
        self.table.setRowCount(len(items))

        for row, r in enumerate(items):
            p_item = QTableWidgetItem(r["proxy"])
            
            if r["alive"]:
                status_item = QTableWidgetItem("Alive")
                status_item.setForeground(Qt.green)
                lat_item = QTableWidgetItem(f"{r['latency_ms']} ms")
            else:
                status_item = QTableWidgetItem("Dead")
                status_item.setForeground(Qt.red)
                lat_item = QTableWidgetItem("-")

            err_item = QTableWidgetItem(r.get("error") or "OK")

            self.table.setItem(row, 0, p_item)
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, lat_item)
            self.table.setItem(row, 3, err_item)

    def _save_and_apply(self):
        text = self.proxy_edit.toPlainText().strip()
        self.proxy_pool.load_proxies(text)
        self.proxy_pool.passive_mode = self.passive_chk.isChecked()
        if self.config is not None:
            self.config.proxies = [e.raw for e in self.proxy_pool.entries]
            self.config.proxy_passive_mode = bool(self.proxy_pool.passive_mode)
            self.config.save()
        self.accept()
