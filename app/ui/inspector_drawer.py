"""
OmniFetch Collapsible Per-Task Bottom Inspector Drawer
Provides 5 dark-themed inspection tabs for the currently selected download:
1. General (URL, save path, Info Hash / ETag, token expiry countdown, resumability, full error, SHA-256 verifier)
2. Chunks / Segments (IDM-style live QPainter Visual Segment Bar + HTTP SQLite segments or Torrent piece summary)
3. Files (Torrent & MEGA folder per-file progress and priorities)
4. Peers & Trackers (Live BitTorrent peers, trackers, seeds, share ratio)
5. Security Log (CyberShield Stage 1/2/3 security_audit records)
"""

import hashlib
import time
from datetime import datetime
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QFormLayout, QTextEdit, QProgressBar, QLineEdit, QApplication
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QBrush, QPen

from .download_table import format_bytes


def _format_expiry(expires_at) -> tuple[str, str]:
    """Returns (human_text, color_hex) for token expiration timestamp."""
    if expires_at is None:
        return "No Expiry", "#9ca3af"
    try:
        exp_ts = float(expires_at)
    except Exception:
        return "No Expiry", "#9ca3af"

    rem = int(exp_ts - time.time())
    if rem <= 0:
        ago = abs(rem)
        if ago < 60:
            return f"Expired ({ago}s ago)", "#ef4444"
        if ago < 3600:
            return f"Expired ({ago // 60}m {ago % 60}s ago)", "#ef4444"
        return f"Expired ({ago // 3600}h {(ago % 3600) // 60}m ago)", "#ef4444"

    mins, secs = divmod(rem, 60)
    hours, mins = divmod(mins, 60)
    if hours > 0:
        return f"Valid ({hours}h {mins}m {secs}s left)", "#10b981"
    if mins > 0:
        return f"Valid ({mins}m {secs}s left)", "#10b981"
    return f"Expiring Soon ({secs}s left)", "#f59e0b"


def compute_file_sha256(file_path: str | Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class SegmentStripWidget(QWidget):
    """IDM-style live QPainter visual segment visualizer."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._segments = []
        self._total_bytes = 0
        self.setFixedHeight(26)

    def set_segments(self, segments: list[dict], total_bytes: int = 0):
        self._segments = list(segments or [])
        self._total_bytes = max(0, int(total_bytes or 0))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = max(1, self.width() - 2)
        h = max(1, self.height() - 2)

        painter.setPen(QPen(QColor("#1f2433"), 1))
        painter.setBrush(QBrush(QColor("#121520")))
        painter.drawRoundedRect(1, 1, w, h, 4, 4)

        if not self._segments:
            painter.end()
            return

        total = self._total_bytes
        if total <= 0:
            total = max((s.get("end_byte", 0) + 1) for s in self._segments)
        if total <= 0:
            total = len(self._segments)

        n = len(self._segments)
        gap = 2
        usable_w = max(n, w - 6 - gap * max(0, n - 1))
        x_cursor = 4.0

        for idx, seg in enumerate(self._segments):
            sb = seg.get("start_byte", 0)
            eb = seg.get("end_byte", 0)
            cb = seg.get("current_byte", sb)
            span = (eb - sb + 1) if (eb >= sb and eb > 0) else 1
            block_w = max(4.0, (span / total) * usable_w) if self._total_bytes > 0 else max(4.0, usable_w / n)
            done = max(0, cb - sb)
            frac = min(1.0, done / max(1, span)) if eb > 0 else (1.0 if seg.get("status") == "COMPLETED" else 0.0)

            st = str(seg.get("status", "PENDING"))
            if st == "COMPLETED":
                fill_col = QColor("#10b981")
            elif st == "FAILED":
                fill_col = QColor("#ef4444")
            elif st == "PENDING":
                fill_col = QColor("#f59e0b")
            else:
                fill_col = QColor("#06b6d4")

            # Segment slot background
            slot_w = max(2, int(block_w))
            if x_cursor + slot_w > w - 2:
                slot_w = max(1, int(w - 2 - x_cursor))
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor("#1d2336")))
            painter.drawRoundedRect(int(x_cursor), 4, slot_w, h - 6, 2, 2)

            if frac > 0:
                fill_w = max(1, int(slot_w * frac))
                painter.setBrush(QBrush(fill_col))
                painter.drawRoundedRect(int(x_cursor), 4, fill_w, h - 6, 2, 2)

            x_cursor += block_w + gap
        painter.end()


class TaskInspectorDrawer(QWidget):
    close_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_task_id = None
        self._sha_cache: dict[tuple, str] = {}
        self._current_sha256: str = ""
        self._init_ui()

    def _init_ui(self):
        self.setObjectName("inspectorDrawer")
        self.setMinimumHeight(210)
        self.setStyleSheet("""
            QWidget#inspectorDrawer {
                background-color: #10131d;
                border-top: 1px solid #1f2433;
            }
            QTabWidget::pane {
                border: none;
                border-top: 1px solid #1f2433;
                background-color: #0d0f17;
            }
            QTabBar::tab {
                background-color: #121520;
                color: #9ca3af;
                padding: 6px 14px;
                border-right: 1px solid #1f2433;
                font-size: 12px;
                font-weight: 500;
            }
            QTabBar::tab:selected {
                background-color: #1a2133;
                color: #00d2ff;
                border-bottom: 2px solid #00d2ff;
            }
            QTableWidget {
                background-color: #0d0f17;
                border: none;
                gridline-color: #171c28;
                color: #e5e7eb;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #121520;
                color: #9ca3af;
                padding: 5px 8px;
                border: none;
                border-bottom: 1px solid #1f2433;
                font-size: 11px;
                font-weight: 600;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Compact header bar
        hdr = QWidget()
        hdr.setStyleSheet("background-color: #121520; border-bottom: 1px solid #1f2433;")
        hdr_layout = QHBoxLayout(hdr)
        hdr_layout.setContentsMargins(12, 4, 8, 4)

        self.lbl_header = QLabel("Task Inspector — Select a download row")
        self.lbl_header.setStyleSheet("color: #e5e7eb; font-weight: 600; font-size: 12px;")
        hdr_layout.addWidget(self.lbl_header)
        hdr_layout.addStretch()

        self.btn_close = QPushButton("Hide")
        self.btn_close.setFixedHeight(22)
        self.btn_close.setStyleSheet("padding: 2px 10px; font-size: 11px;")
        self.btn_close.clicked.connect(self.close_requested.emit)
        hdr_layout.addWidget(self.btn_close)
        layout.addWidget(hdr)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Tab 1: General + SHA-256 Integrity Verifier
        self.general_widget = QWidget()
        gen_layout = QFormLayout(self.general_widget)
        gen_layout.setContentsMargins(14, 10, 14, 10)
        gen_layout.setSpacing(6)

        def _ro_lbl():
            lbl = QLabel("--")
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color: #e5e7eb;")
            return lbl

        self.lbl_gen_url = _ro_lbl()
        self.lbl_gen_dest = _ro_lbl()
        self.lbl_gen_validator = _ro_lbl()
        self.lbl_gen_expiry = _ro_lbl()
        self.lbl_gen_resumable = _ro_lbl()
        self.txt_gen_error = QTextEdit()
        self.txt_gen_error.setReadOnly(True)
        self.txt_gen_error.setMaximumHeight(42)
        self.txt_gen_error.setStyleSheet(
            "background-color: #121520; border: 1px solid #1f2433; color: #fca5a5; font-size: 11px; padding: 4px;"
        )

        # SHA-256 Integrity Verifier row
        sha_row = QWidget()
        sha_layout = QHBoxLayout(sha_row)
        sha_layout.setContentsMargins(0, 0, 0, 0)
        sha_layout.setSpacing(6)
        self.txt_sha256 = QLineEdit()
        self.txt_sha256.setReadOnly(True)
        self.txt_sha256.setPlaceholderText("Computed on COMPLETED single files")
        self.txt_sha256.setStyleSheet("font-size: 11px; padding: 4px 8px;")
        self.btn_copy_sha = QPushButton("Copy")
        self.btn_copy_sha.setFixedHeight(26)
        self.btn_copy_sha.setStyleSheet("padding: 2px 10px; font-size: 11px;")
        self.btn_copy_sha.clicked.connect(self._copy_sha256)
        self.txt_expected_sha = QLineEdit()
        self.txt_expected_sha.setPlaceholderText("Paste expected SHA-256 to verify...")
        self.txt_expected_sha.setStyleSheet("font-size: 11px; padding: 4px 8px;")
        self.txt_expected_sha.textChanged.connect(self._verify_sha_input)
        self.lbl_sha_status = QLabel("")
        self.lbl_sha_status.setStyleSheet("font-size: 11px; font-weight: 600;")

        sha_layout.addWidget(self.txt_sha256, 2)
        sha_layout.addWidget(self.btn_copy_sha)
        sha_layout.addWidget(self.txt_expected_sha, 2)
        sha_layout.addWidget(self.lbl_sha_status)

        gen_layout.addRow("Full URL:", self.lbl_gen_url)
        gen_layout.addRow("Save Path:", self.lbl_gen_dest)
        gen_layout.addRow("Info Hash / ETag:", self.lbl_gen_validator)
        gen_layout.addRow("Token Expiry:", self.lbl_gen_expiry)
        gen_layout.addRow("Resumable:", self.lbl_gen_resumable)
        gen_layout.addRow("SHA-256 Verifier:", sha_row)
        gen_layout.addRow("Error Message:", self.txt_gen_error)
        self.tabs.addTab(self.general_widget, "General")

        # Tab 2: Chunks / Segments (IDM Visual Segment Strip + Table)
        seg_tab = QWidget()
        seg_layout = QVBoxLayout(seg_tab)
        seg_layout.setContentsMargins(8, 6, 8, 4)
        seg_layout.setSpacing(6)
        self.segment_strip = SegmentStripWidget(seg_tab)
        seg_layout.addWidget(self.segment_strip)
        self.segments_table = self._make_table(["Segment / Scope", "Byte Range", "Downloaded", "Progress", "Status"])
        seg_layout.addWidget(self.segments_table)
        self.tabs.addTab(seg_tab, "Chunks / Segments")

        # Tab 3: Files
        self.files_table = self._make_table(["File Path", "Size", "Downloaded", "Priority", "Progress"])
        self.tabs.addTab(self.files_table, "Files")

        # Tab 4: Peers & Trackers
        peers_tab = QWidget()
        peers_layout = QVBoxLayout(peers_tab)
        peers_layout.setContentsMargins(8, 6, 8, 6)
        peers_layout.setSpacing(6)

        self.lbl_peer_summary = QLabel("Seeds: --  |  Peers: --  |  Share Ratio: --")
        self.lbl_peer_summary.setStyleSheet("color: #00d2ff; font-size: 12px; font-weight: 600;")
        peers_layout.addWidget(self.lbl_peer_summary)

        split_row = QHBoxLayout()
        self.peers_table = self._make_table(["Peer IP", "Client", "Down", "Up", "Progress"])
        self.trackers_table = self._make_table(["Tracker URL", "Tier", "Status / Detail"])
        split_row.addWidget(self.peers_table, 3)
        split_row.addWidget(self.trackers_table, 2)
        peers_layout.addLayout(split_row)
        self.tabs.addTab(peers_tab, "Peers & Trackers")

        # Tab 5: Security Log
        self.security_table = self._make_table(["Timestamp", "Stage", "Verdict", "Threat", "Details"])
        self.tabs.addTab(self.security_table, "Security Log")

    def _make_table(self, headers: list[str]) -> QTableWidget:
        tbl = QTableWidget()
        tbl.setColumnCount(len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        tbl.verticalHeader().setVisible(False)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        hdr = tbl.horizontalHeader()
        for idx in range(len(headers)):
            mode = QHeaderView.Stretch if idx in (0, len(headers) - 1) and len(headers) <= 4 else QHeaderView.ResizeToContents
            hdr.setSectionResizeMode(idx, mode)
        if len(headers) >= 1:
            hdr.setSectionResizeMode(0, QHeaderView.Interactive)
            hdr.setStretchLastSection(True)
        return tbl

    def _copy_sha256(self):
        if self._current_sha256:
            cb = QApplication.clipboard()
            if cb:
                cb.setText(self._current_sha256)

    def _verify_sha_input(self, *_args):
        expected = self.txt_expected_sha.text().strip().lower()
        if not expected or not self._current_sha256:
            self.lbl_sha_status.setText("")
            return None
        match = (expected == self._current_sha256.lower())
        if match:
            self.lbl_sha_status.setText("Verified Match")
            self.lbl_sha_status.setStyleSheet("color: #10b981; font-size: 11px; font-weight: 600;")
        else:
            self.lbl_sha_status.setText("Hash Mismatch")
            self.lbl_sha_status.setStyleSheet("color: #ef4444; font-size: 11px; font-weight: 600;")
        return match

    def update_for_task(self, task: dict | None, engine_manager=None):
        """Refreshes all 5 tabs safely for the selected task."""
        if not task:
            self._current_task_id = None
            self._current_sha256 = ""
            self.lbl_header.setText("Task Inspector — No task selected")
            self.lbl_gen_url.setText("--")
            self.lbl_gen_dest.setText("--")
            self.lbl_gen_validator.setText("--")
            self.lbl_gen_expiry.setText("--")
            self.lbl_gen_resumable.setText("--")
            self.txt_sha256.setText("")
            self.lbl_sha_status.setText("")
            self.txt_gen_error.setPlainText("")
            self.segment_strip.set_segments([], 0)
            for tbl in (self.segments_table, self.files_table, self.peers_table, self.trackers_table, self.security_table):
                tbl.setRowCount(0)
            self.lbl_peer_summary.setText("Seeds: --  |  Peers: --  |  Share Ratio: --")
            return

        tid = task.get("id")
        if tid != self._current_task_id:
            self.txt_expected_sha.clear()
        self._current_task_id = tid
        self.lbl_header.setText(f"Inspector — {task.get('filename', tid)}  [{task.get('engine_type', 'HTTP')} • {task.get('status', '')}]")

        # 1. General Tab
        self.lbl_gen_url.setText(str(task.get("url") or "--"))
        dest = str(task.get("destination") or "--")
        fn = str(task.get("filename") or "")
        full_dest = Path(dest) / fn if dest != "--" and fn else None
        self.lbl_gen_dest.setText(str(full_dest) if full_dest else dest)

        validator_parts = []
        if task.get("info_hash"):
            validator_parts.append(f"InfoHash: {task['info_hash']}")
        if task.get("etag"):
            validator_parts.append(f"ETag: {task['etag']}")
        if task.get("last_modified"):
            validator_parts.append(f"Last-Modified: {task['last_modified']}")
        self.lbl_gen_validator.setText("  |  ".join(validator_parts) if validator_parts else "--")

        exp_text, exp_color = _format_expiry(task.get("expires_at"))
        self.lbl_gen_expiry.setText(exp_text)
        self.lbl_gen_expiry.setStyleSheet(f"color: {exp_color}; font-weight: 600;")

        res_val = task.get("resumable", -1)
        self.lbl_gen_resumable.setText("Yes" if res_val == 1 else ("No" if res_val == 0 else "Checking"))
        self.txt_gen_error.setPlainText(str(task.get("error_message") or "None"))

        # SHA-256 computation for completed single file
        self._current_sha256 = ""
        if task.get("status") == "COMPLETED" and full_dest and full_dest.is_file():
            try:
                st = full_dest.stat()
                cache_key = (str(full_dest), st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime)))
                if cache_key not in self._sha_cache and st.st_size <= 512 * 1024 * 1024:
                    self._sha_cache[cache_key] = compute_file_sha256(full_dest)
                self._current_sha256 = self._sha_cache.get(cache_key, "")
            except Exception:
                self._current_sha256 = ""
        self.txt_sha256.setText(self._current_sha256)
        self._verify_sha_input()

        # 2. Chunks / Segments Tab
        self._populate_segments_tab(task, engine_manager)

        # 3. Files Tab
        self._populate_files_tab(task, engine_manager)

        # 4. Peers & Trackers Tab
        self._populate_peers_tab(task, engine_manager)

        # 5. Security Log Tab
        self._populate_security_tab(task, engine_manager)

    def _populate_segments_tab(self, task: dict, engine_manager):
        tid = task["id"]
        eng = task.get("engine_type", "HTTP")
        if eng == "HTTP" and engine_manager and engine_manager.db:
            segs = engine_manager.db.get_segments(tid)
            if segs:
                self.segment_strip.set_segments(segs, task.get("total_bytes", 0) or 0)
                self.segments_table.setRowCount(len(segs))
                for r, s in enumerate(segs):
                    sb = s.get("start_byte", 0)
                    eb = s.get("end_byte", 0)
                    cb = s.get("current_byte", sb)
                    done = max(0, cb - sb)
                    span = max(1, (eb - sb + 1)) if eb >= sb and eb > 0 else max(1, done)
                    pct = min(100, int((done / span) * 100)) if eb > 0 else (100 if s.get("status") == "COMPLETED" else 0)

                    self.segments_table.setItem(r, 0, QTableWidgetItem(f"Segment #{s.get('segment_index', r)}"))
                    self.segments_table.setItem(r, 1, QTableWidgetItem(f"{sb} - {eb}" if eb > 0 else f"{sb}+"))
                    self.segments_table.setItem(r, 2, QTableWidgetItem(format_bytes(done)))

                    bar = QProgressBar()
                    bar.setRange(0, 100)
                    bar.setValue(pct)
                    bar.setFixedHeight(16)
                    self.segments_table.setCellWidget(r, 3, bar)

                    st_item = QTableWidgetItem(str(s.get("status", "")))
                    self.segments_table.setItem(r, 4, st_item)
                return

        if eng == "TORRENT" and engine_manager and getattr(engine_manager, "torrent_session", None):
            handle = engine_manager.torrent_session.active_handles.get(tid)
            if handle and handle.is_valid():
                try:
                    st = handle.status()
                    ti = handle.torrent_file() if st.has_metadata else None
                    if ti:
                        num_p = ti.num_pieces()
                        p_len = ti.piece_length()
                        have_p = st.num_pieces
                        pct = int((have_p / max(1, num_p)) * 100)
                        self.segment_strip.set_segments([{
                            "start_byte": 0,
                            "end_byte": max(1, num_p) - 1,
                            "current_byte": have_p,
                            "status": "COMPLETED" if have_p >= num_p else "DOWNLOADING",
                        }], num_p)
                        self.segments_table.setRowCount(1)
                        self.segments_table.setItem(0, 0, QTableWidgetItem(f"Pieces ({format_bytes(p_len)} each)"))
                        self.segments_table.setItem(0, 1, QTableWidgetItem(f"{have_p} / {num_p} pieces"))
                        self.segments_table.setItem(0, 2, QTableWidgetItem(format_bytes(st.total_done)))
                        bar = QProgressBar()
                        bar.setRange(0, 100)
                        bar.setValue(pct)
                        bar.setFixedHeight(16)
                        self.segments_table.setCellWidget(0, 3, bar)
                        self.segments_table.setItem(0, 4, QTableWidgetItem(str(st.state)))
                        return
                except Exception:
                    pass

        tot = task.get("total_bytes", 0) or 0
        dl = task.get("downloaded_bytes", 0) or 0
        pct = min(100, int((dl / tot) * 100)) if tot > 0 else (100 if task.get("status") == "COMPLETED" else 0)
        self.segment_strip.set_segments([{
            "start_byte": 0,
            "end_byte": max(1, tot) - 1,
            "current_byte": dl,
            "status": task.get("status", "PENDING"),
        }], tot)
        self.segments_table.setRowCount(1)
        self.segments_table.setItem(0, 0, QTableWidgetItem("Stream #0"))
        self.segments_table.setItem(0, 1, QTableWidgetItem(f"0 - {tot - 1}" if tot > 0 else "Unknown"))
        self.segments_table.setItem(0, 2, QTableWidgetItem(format_bytes(dl)))
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setFixedHeight(16)
        self.segments_table.setCellWidget(0, 3, bar)
        self.segments_table.setItem(0, 4, QTableWidgetItem(str(task.get("status", ""))))

    def _populate_files_tab(self, task: dict, engine_manager):
        tid = task["id"]
        eng = task.get("engine_type", "HTTP")
        prios = task.get("file_priorities") or []

        if eng == "TORRENT" and engine_manager and getattr(engine_manager, "torrent_session", None):
            handle = engine_manager.torrent_session.active_handles.get(tid)
            ti = None
            file_prog = []
            if handle and handle.is_valid():
                try:
                    st = handle.status()
                    if st.has_metadata:
                        ti = handle.torrent_file()
                        file_prog = handle.file_progress()
                        if not prios:
                            prios = list(handle.get_file_priorities())
                except Exception:
                    ti = None
            if ti is None and task.get("torrent_path"):
                try:
                    import libtorrent as lt
                    ti = lt.torrent_info(str(task["torrent_path"]))
                except Exception:
                    ti = None
            if ti is not None:
                fs = ti.files()
                n_files = fs.num_files()
                self.files_table.setRowCount(n_files)
                for idx in range(n_files):
                    f_path = fs.file_path(idx)
                    f_size = fs.file_size(idx)
                    f_done = file_prog[idx] if idx < len(file_prog) else 0
                    p_val = prios[idx] if idx < len(prios) else 4
                    p_label = "Skip (0)" if p_val == 0 else ("High (7)" if p_val >= 7 else f"Normal ({p_val})")
                    pct = min(100, int((f_done / max(1, f_size)) * 100)) if p_val > 0 else 0

                    self.files_table.setItem(idx, 0, QTableWidgetItem(f_path))
                    self.files_table.setItem(idx, 1, QTableWidgetItem(format_bytes(f_size)))
                    self.files_table.setItem(idx, 2, QTableWidgetItem(format_bytes(f_done)))
                    self.files_table.setItem(idx, 3, QTableWidgetItem(p_label))
                    bar = QProgressBar()
                    bar.setRange(0, 100)
                    bar.setValue(pct)
                    bar.setFixedHeight(16)
                    self.files_table.setCellWidget(idx, 4, bar)
                return

        if eng == "MEGA":
            sel_indices = task.get("selected_indices")
            staging_dir = Path(task.get("staging_path") or "")
            staged_files = [p for p in staging_dir.rglob("*") if p.is_file()] if staging_dir.exists() else []
            if staged_files:
                self.files_table.setRowCount(len(staged_files))
                for r, fp in enumerate(staged_files):
                    rel = str(fp.relative_to(staging_dir))
                    sz = fp.stat().st_size
                    self.files_table.setItem(r, 0, QTableWidgetItem(rel))
                    self.files_table.setItem(r, 1, QTableWidgetItem(format_bytes(sz)))
                    self.files_table.setItem(r, 2, QTableWidgetItem(format_bytes(sz)))
                    self.files_table.setItem(r, 3, QTableWidgetItem("Selected"))
                    bar = QProgressBar()
                    bar.setRange(0, 100)
                    bar.setValue(100 if task.get("status") == "COMPLETED" else 50)
                    bar.setFixedHeight(16)
                    self.files_table.setCellWidget(r, 4, bar)
                return
            if sel_indices:
                self.files_table.setRowCount(len(sel_indices))
                for r, idx in enumerate(sel_indices):
                    self.files_table.setItem(r, 0, QTableWidgetItem(f"MEGA Node Index #{idx}"))
                    self.files_table.setItem(r, 1, QTableWidgetItem("--"))
                    self.files_table.setItem(r, 2, QTableWidgetItem("--"))
                    self.files_table.setItem(r, 3, QTableWidgetItem("Selected (Normal)"))
                    self.files_table.setItem(r, 4, QTableWidgetItem(str(task.get("status", ""))))
                return

        tot = task.get("total_bytes", 0) or 0
        dl = task.get("downloaded_bytes", 0) or 0
        pct = min(100, int((dl / tot) * 100)) if tot > 0 else (100 if task.get("status") == "COMPLETED" else 0)
        self.files_table.setRowCount(1)
        self.files_table.setItem(0, 0, QTableWidgetItem(str(task.get("filename", ""))))
        self.files_table.setItem(0, 1, QTableWidgetItem(format_bytes(tot) if tot > 0 else "Unknown"))
        self.files_table.setItem(0, 2, QTableWidgetItem(format_bytes(dl)))
        self.files_table.setItem(0, 3, QTableWidgetItem("Normal"))
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setFixedHeight(16)
        self.files_table.setCellWidget(0, 4, bar)

    def _populate_peers_tab(self, task: dict, engine_manager):
        tid = task["id"]
        if task.get("engine_type") != "TORRENT" or not engine_manager or not getattr(engine_manager, "torrent_session", None):
            self.lbl_peer_summary.setText("Peers & Trackers apply to active BitTorrent tasks.")
            self.peers_table.setRowCount(0)
            self.trackers_table.setRowCount(0)
            return

        handle = engine_manager.torrent_session.active_handles.get(tid)
        if not handle or not handle.is_valid():
            self.lbl_peer_summary.setText(f"Torrent handle inactive ({task.get('status', 'PAUSED')}).")
            self.peers_table.setRowCount(0)
            self.trackers_table.setRowCount(0)
            return

        try:
            st = handle.status()
            ratio = st.all_time_upload / max(1, st.all_time_download)
            self.lbl_peer_summary.setText(
                f"Seeds: {st.num_seeds}  |  Peers: {st.num_peers}  |  "
                f"Down: {format_bytes(st.download_rate)}/s  |  "
                f"Up: {format_bytes(st.upload_rate)}/s  |  Ratio: {ratio:.2f}"
            )

            peers = handle.get_peer_info()
            self.peers_table.setRowCount(len(peers))
            for r, p in enumerate(peers):
                self.peers_table.setItem(r, 0, QTableWidgetItem(f"{p.ip[0]}:{p.ip[1]}"))
                self.peers_table.setItem(r, 1, QTableWidgetItem(str(getattr(p, "client", "") or "Peer")))
                self.peers_table.setItem(r, 2, QTableWidgetItem(f"{format_bytes(p.down_speed)}/s"))
                self.peers_table.setItem(r, 3, QTableWidgetItem(f"{format_bytes(p.up_speed)}/s"))
                self.peers_table.setItem(r, 4, QTableWidgetItem(f"{int(getattr(p, 'progress', 0) * 100)}%"))

            trackers = handle.trackers()
            self.trackers_table.setRowCount(len(trackers))
            for r, tr in enumerate(trackers):
                if isinstance(tr, dict):
                    url = tr.get("url", "")
                    tier = str(tr.get("tier", 0))
                    fails = tr.get("fails", 0)
                    msg = tr.get("message") or ("OK" if fails == 0 else f"Fails: {fails}")
                else:
                    url = getattr(tr, "url", "")
                    tier = str(getattr(tr, "tier", 0))
                    msg = getattr(tr, "message", "") or "Configured"
                self.trackers_table.setItem(r, 0, QTableWidgetItem(str(url)))
                self.trackers_table.setItem(r, 1, QTableWidgetItem(tier))
                self.trackers_table.setItem(r, 2, QTableWidgetItem(str(msg)))
        except Exception:
            self.peers_table.setRowCount(0)
            self.trackers_table.setRowCount(0)

    def _populate_security_tab(self, task: dict, engine_manager):
        tid = task["id"]
        rows = []
        if engine_manager and engine_manager.db and hasattr(engine_manager.db, "get_security_audit"):
            rows = engine_manager.db.get_security_audit(tid)

        self.security_table.setRowCount(len(rows))
        for r, entry in enumerate(rows):
            ts_str = datetime.fromtimestamp(entry.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            verdict = str(entry.get("verdict", ""))
            self.security_table.setItem(r, 0, QTableWidgetItem(ts_str))
            self.security_table.setItem(r, 1, QTableWidgetItem(str(entry.get("stage", ""))))
            v_item = QTableWidgetItem(verdict)
            if "CRITICAL" in verdict or "BLOCK" in verdict:
                v_item.setForeground(QColor("#ef4444"))
            elif "WARNING" in verdict:
                v_item.setForeground(QColor("#f59e0b"))
            else:
                v_item.setForeground(QColor("#10b981"))
            self.security_table.setItem(r, 2, v_item)
            self.security_table.setItem(r, 3, QTableWidgetItem(str(entry.get("threat_name") or "--")))
            self.security_table.setItem(r, 4, QTableWidgetItem(str(entry.get("details") or "")))
