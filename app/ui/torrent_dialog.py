"""
OmniFetch Torrent & Magnet Inspection Dialog
Displays torrent metadata file tree BEFORE downloading any payload bytes.
Auto-unchecks critical traps (red badge), flags game executables (amber badge),
and allows selective file prioritization and sequential mode.
"""

import os
import shutil
from pathlib import Path
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QCheckBox, QComboBox, QFileDialog, QFrame, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from ..engines.torrent.file_tree import TorrentFileInspector
from .download_table import format_bytes

class TorrentDialog(QDialog):
    def __init__(self, torrent_name, files, default_dest=None, parent=None, default_stop_ratio=0.0):
        super().__init__(parent)
        self.torrent_name = torrent_name
        self.raw_files = files
        self.default_dest = default_dest or str(Path.home() / "Downloads" / "OmniFetch")
        self.default_stop_ratio = float(default_stop_ratio if default_stop_ratio is not None else 0.0)
        self.inspection = TorrentFileInspector.inspect_file_tree(self.raw_files)
        self.inspected_files = self.inspection["files"]
        self.result_data = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"Torrent Inspection — {self.torrent_name}")
        self.resize(780, 560)
        self.setStyleSheet("""
            QDialog { background-color: #121520; color: #f3f4f6; }
            QLabel { color: #f3f4f6; }
            QTableWidget {
                background-color: #0d0f17;
                border: 1px solid #1f2433;
                gridline-color: #171c28;
                color: #e5e7eb;
                selection-background-color: #1c2336;
            }
            QHeaderView::section {
                background-color: #121520;
                color: #9ca3af;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #1f2433;
                font-weight: 600;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #0d0f17;
                border: 1px solid #2b334a;
                border-radius: 4px;
                padding: 6px 10px;
                color: #f3f4f6;
            }
            QPushButton {
                background-color: #1a1f2e;
                border: 1px solid #2b334a;
                border-radius: 6px;
                padding: 8px 16px;
                color: #f3f4f6;
                font-weight: 500;
            }
            QPushButton:hover { background-color: #242c40; }
            QPushButton#btnStart {
                background-color: #0070f3;
                border: 1px solid #0060df;
                font-weight: 600;
            }
            QPushButton#btnStart:hover { background-color: #0060df; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        # Header: Torrent Name & Total Size
        total_bytes = sum(f["size"] for f in self.inspected_files)
        lbl_title = QLabel(f"<strong>Torrent:</strong> {self.torrent_name} ({format_bytes(total_bytes)})")
        lbl_title.setStyleSheet("font-size: 14px;")
        layout.addWidget(lbl_title)

        # Security Summary Banner
        traps = self.inspection["trap_count"]
        reviews = self.inspection["review_count"]
        self.banner = QLabel()
        if traps > 0:
            self.banner.setText(
                f"<strong>Stage 1 Security Alert:</strong> {traps} Critical Trap file(s) detected and <strong>AUTO-UNCHECKED</strong>."
            )
            self.banner.setStyleSheet(
                "background-color: #2b1115; color: #ef4444; border: 1px solid #7f1d1d; border-radius: 6px; padding: 8px 12px;"
            )
        elif reviews > 0:
            self.banner.setText(
                f"<strong>Stage 1 Notice:</strong> {reviews} Executable/Installer asset(s) flagged for review (kept checked; will pass Stage 3 scan)."
            )
            self.banner.setStyleSheet(
                "background-color: #2b2311; color: #f59e0b; border: 1px solid #78350f; border-radius: 6px; padding: 8px 12px;"
            )
        else:
            self.banner.setText("<strong>Stage 1 Security Gate:</strong> All files verified clean.")
            self.banner.setStyleSheet(
                "background-color: #112b1c; color: #10b981; border: 1px solid #064e3b; border-radius: 6px; padding: 8px 12px;"
            )
        layout.addWidget(self.banner)

        # File Tree Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Download", "File Path", "Size", "Security Classification"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setRowCount(len(self.inspected_files))

        self.checkboxes = []

        for row, f in enumerate(self.inspected_files):
            # Checkbox item
            chk = QCheckBox()
            chk.setChecked(f["checked"])
            chk.stateChanged.connect(self._on_checkbox_toggled)
            self.checkboxes.append(chk)

            # Center checkbox in cell
            chk_widget = QFrame()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.addWidget(chk)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            self.table.setCellWidget(row, 0, chk_widget)

            # Path item
            item_path = QTableWidgetItem(f["path"])
            item_path.setToolTip(f.get("reason", ""))
            self.table.setItem(row, 1, item_path)

            # Size item
            item_size = QTableWidgetItem(format_bytes(f["size"]))
            item_size.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 2, item_size)

            # Security Badge item
            item_sec = QTableWidgetItem(f["badge"])
            if f["severity"] == "CRITICAL":
                item_sec.setForeground(QColor("#ef4444"))
            elif f["severity"] == "LOW":
                item_sec.setForeground(QColor("#f59e0b"))
            else:
                item_sec.setForeground(QColor("#10b981"))
            self.table.setItem(row, 3, item_sec)

        layout.addWidget(self.table)

        # Options Row: Select All / Uncheck Traps + Sequential Download
        opts_layout = QHBoxLayout()
        btn_select_all = QPushButton("Select All")
        btn_select_all.clicked.connect(self._select_all)
        opts_layout.addWidget(btn_select_all)

        btn_uncheck_traps = QPushButton("Uncheck Traps")
        btn_uncheck_traps.clicked.connect(self._uncheck_traps)
        opts_layout.addWidget(btn_uncheck_traps)

        opts_layout.addStretch()

        self.chk_sequential = QCheckBox("Sequential Download (Streaming Mode)")
        opts_layout.addWidget(self.chk_sequential)

        if self.default_stop_ratio <= 0.0:
            stop_label = "Auto-stop Seeding on Completion (Ratio 0.0)"
        else:
            stop_label = f"Auto-stop Seeding at Ratio {self.default_stop_ratio:.2f}"
        self.chk_auto_stop = QCheckBox(stop_label)
        self.chk_auto_stop.setChecked(self.default_stop_ratio >= 0.0)
        opts_layout.addWidget(self.chk_auto_stop)

        layout.addLayout(opts_layout)

        # Destination Folder
        dest_layout = QHBoxLayout()
        dest_layout.addWidget(QLabel("Save Folder:"))
        self.txt_dest = QLineEdit(self.default_dest)
        self.txt_dest.textChanged.connect(lambda *_: self._check_disk_space())
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._on_browse)
        dest_layout.addWidget(self.txt_dest)
        dest_layout.addWidget(btn_browse)
        layout.addLayout(dest_layout)

        self.lbl_disk_warning = QLabel("")
        self.lbl_disk_warning.setVisible(False)
        self.lbl_disk_warning.setWordWrap(True)
        self.lbl_disk_warning.setStyleSheet(
            "background-color: #2b2311; color: #f59e0b; border: 1px solid #78350f; border-radius: 6px; padding: 6px 10px;"
        )
        layout.addWidget(self.lbl_disk_warning)
        self._check_disk_space()

        # Action Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        self.btn_start = QPushButton("Start Download")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.clicked.connect(self._on_start)
        btn_box.addWidget(self.btn_start)

        layout.addLayout(btn_box)

    def _on_browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Save Folder", self.txt_dest.text())
        if folder:
            self.txt_dest.setText(folder)

    def _check_disk_space(self) -> bool:
        selected_bytes = sum(f["size"] for f in self.inspected_files if f.get("checked", True))
        target = Path(self.txt_dest.text().strip() or self.default_dest)
        probe = target
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        try:
            free_b = shutil.disk_usage(str(probe)).free
        except Exception:
            free_b = -1

        if selected_bytes > 0 and free_b >= 0 and free_b < selected_bytes + 50 * 1024 * 1024:
            self.lbl_disk_warning.setText(
                f"Low Disk Space: Selected files require {format_bytes(selected_bytes)} (+50 MB reserve), "
                f"only {format_bytes(free_b)} free on {probe}."
            )
            self.lbl_disk_warning.setVisible(True)
            return False
        self.lbl_disk_warning.setVisible(False)
        return True

    def _on_checkbox_toggled(self):
        # Update checked state in inspected files
        for row, chk in enumerate(self.checkboxes):
            self.inspected_files[row]["checked"] = chk.isChecked()
            self.inspected_files[row]["priority"] = 4 if chk.isChecked() else 0
        if hasattr(self, "lbl_disk_warning"):
            self._check_disk_space()

    def _select_all(self):
        for chk in self.checkboxes:
            chk.setChecked(True)

    def _uncheck_traps(self):
        for row, f in enumerate(self.inspected_files):
            if f["severity"] == "CRITICAL":
                self.checkboxes[row].setChecked(False)

    def _on_start(self):
        self._on_checkbox_toggled()
        priorities = [f["priority"] for f in self.inspected_files]
        if all(p == 0 for p in priorities):
            QMessageBox.warning(self, "No Files Selected", "Please select at least one file to download.")
            return
        if not self._check_disk_space():
            reply = QMessageBox.warning(
                self,
                "Insufficient Disk Space",
                f"{self.lbl_disk_warning.text()}\n\nStart torrent anyway?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        stop_ratio = self.default_stop_ratio if self.chk_auto_stop.isChecked() else -1.0
        self.result_data = {
            "destination": self.txt_dest.text().strip(),
            "file_priorities": priorities,
            "sequential": self.chk_sequential.isChecked(),
            "stop_ratio": stop_ratio,
            "files": self.inspected_files
        }
        self.accept()
