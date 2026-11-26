"""
OmniFetch New Download Dialog
Supports Single Download probing + Disk Space Guard + Stage 1 Pre-Download Check,
plus a Batch Links tab for multi-line URL/magnet/MEGA import or .txt file loading.
"""

import os
import re
import asyncio
from pathlib import Path
from urllib.parse import urlparse, unquote
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QFileDialog, QMessageBox,
    QTabWidget, QWidget, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QCheckBox, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor

from .icons import get_icon
from ..engines.mega.resolver import MegaUrlResolver
from ..core.logger import get_logger

logger = get_logger("add_dialog")


def parse_batch_links_text(raw_text: str) -> list[dict]:
    """Extracts deduplicated HTTP/HTTPS/Magnet/MEGA links from multi-line or .txt input."""
    if not raw_text or not isinstance(raw_text, str):
        return []
    candidates = re.findall(r'(?:magnet:\?xt=urn:btih:[^\s\'"]+|https?://[^\s\'"]+)', raw_text, re.IGNORECASE)
    seen = set()
    items = []
    for raw in candidates:
        url = raw.strip().strip("'\"<>")
        if not url or url in seen:
            continue
        seen.add(url)
        low = url.lower()
        if low.startswith("magnet:") or urlparse(url).path.lower().endswith(".torrent"):
            eng = "TORRENT"
            dn = re.search(r'[?&]dn=([^&]+)', url)
            fn = unquote(dn.group(1).replace("+", " ")) if dn else (Path(urlparse(url).path).name or "Magnet Download")
        elif MegaUrlResolver.is_mega_url(url):
            eng = "MEGA"
            parsed_m = MegaUrlResolver.parse_url(url) or {}
            fn = f"MEGA_{parsed_m.get('id', 'item')}"
        else:
            eng = "HTTP"
            fn = Path(unquote(urlparse(url).path)).name or "download.bin"
        items.append({"url": url, "engine_type": eng, "filename": fn})
    return items


class ProbeWorker(QThread):
    probed = Signal(dict)
    _active_workers = set()

    def __init__(self, engine_manager, url):
        super().__init__()
        self.engine_manager = engine_manager
        self.url = url
        self._cancelled = False
        self._loop = None
        self._task = None
        ProbeWorker._active_workers.add(self)
        self.finished.connect(self._cleanup_ref)

    def _cleanup_ref(self):
        ProbeWorker._active_workers.discard(self)

    def cancel(self):
        self._cancelled = True
        if self._loop and self._task and not self._task.done():
            try:
                self._loop.call_soon_threadsafe(self._task.cancel)
            except Exception:
                pass

    def run(self):
        if self._cancelled:
            return
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            if self._cancelled:
                return
            self._task = loop.create_task(self.engine_manager.probe_url(self.url))
            res = loop.run_until_complete(self._task)
            if not self._cancelled:
                self.probed.emit(res if isinstance(res, dict) else {})
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"ProbeWorker exception for {self.url}: {e}")
            if not self._cancelled:
                self.probed.emit({"error": str(e)})
        finally:
            self._task = None
            self._loop = None
            try:
                loop.close()
            except Exception:
                pass


class AddDownloadDialog(QDialog):
    def __init__(self, engine_manager, default_dest=None, parent=None):
        super().__init__(parent)
        self.engine_manager = engine_manager
        self.default_dest = default_dest or str(Path.home() / "Downloads" / "OmniFetch")
        self.probe_worker = None
        self._pending_probe_url = None
        self._probed_resumable = -1
        self._probed_total_bytes = 0
        self._probe_timer = QTimer(self)
        self._probe_timer.setSingleShot(True)
        self._probe_timer.timeout.connect(self._start_pending_probe)
        self.result_data = None
        self.batch_results: list[dict] = []
        self._batch_preview_items: list[dict] = []
        self._batch_checkboxes: list[QCheckBox] = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("New Download — OmniFetch")
        self.setMinimumWidth(620)
        self.setStyleSheet("""
            QDialog { background-color: #121520; }
            QLabel { color: #f3f4f6; font-size: 13px; }
            QLineEdit, QTextEdit { background-color: #0d0f17; border: 1px solid #2b334a; border-radius: 6px; padding: 8px 12px; color: #fff; }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #00d2ff; }
            QComboBox { background-color: #0d0f17; border: 1px solid #2b334a; border-radius: 6px; padding: 7px 12px; color: #fff; }
            QComboBox:disabled { color: #6b7280; background-color: #161924; }
            QComboBox QAbstractItemView { background-color: #121520; color: #f3f4f6; selection-background-color: #0070f3; }
            QPushButton { background-color: #1a1f2e; border: 1px solid #2b334a; border-radius: 6px; padding: 8px 16px; color: #fff; font-weight: 500; }
            QPushButton:hover { background-color: #242c40; }
            QPushButton#btnDownload { background-color: #0070f3; border: 1px solid #0060df; font-weight: 600; }
            QPushButton#btnDownload:hover { background-color: #0060df; }
        """)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)

        # ---- TAB 1: Single Download ----
        tab_single = QWidget()
        layout = QVBoxLayout(tab_single)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        layout.addWidget(QLabel("Download Link (HTTP, HTTPS, Magnet, MEGA) or Torrent file:"))
        url_layout = QHBoxLayout()
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://... or magnet:?xt=... or select .torrent file")
        self.txt_url.textChanged.connect(self._on_url_changed)
        btn_open_torrent = QPushButton(".torrent...")
        btn_open_torrent.setIcon(get_icon("folder"))
        btn_open_torrent.setToolTip("Open local .torrent file")
        btn_open_torrent.clicked.connect(self._on_open_torrent_file)
        url_layout.addWidget(self.txt_url)
        url_layout.addWidget(btn_open_torrent)
        layout.addLayout(url_layout)

        layout.addWidget(QLabel("File Name:"))
        self.txt_filename = QLineEdit()
        self.txt_filename.setPlaceholderText("auto-detected on probe")
        self.txt_filename.textChanged.connect(self._evaluate_security_gate)
        layout.addWidget(self.txt_filename)

        layout.addWidget(QLabel("Save Folder:"))
        dest_layout = QHBoxLayout()
        self.txt_dest = QLineEdit(self.default_dest)
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._on_browse)
        dest_layout.addWidget(self.txt_dest)
        dest_layout.addWidget(btn_browse)
        layout.addLayout(dest_layout)

        conn_layout = QHBoxLayout()
        conn_layout.addWidget(QLabel("Parallel Connections:"))
        self.combo_segments = QComboBox()
        self.combo_segments.addItems(["1 (Single)", "2 Segments", "4 Segments", "8 Segments (Recommended)", "16 Segments (Max)"])
        self.combo_segments.setCurrentIndex(3)
        conn_layout.addWidget(self.combo_segments)
        layout.addLayout(conn_layout)

        self.lbl_resumable = QLabel("Resume Capability: Checking on link input")
        self.lbl_resumable.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")
        layout.addWidget(self.lbl_resumable)

        self.lbl_security = QLabel("Stage 1 Security Check: Enter link to evaluate")
        self.lbl_security.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")
        layout.addWidget(self.lbl_security)

        self.lbl_disk_warning = QLabel("")
        self.lbl_disk_warning.setVisible(False)
        self.lbl_disk_warning.setWordWrap(True)
        self.lbl_disk_warning.setStyleSheet("color: #f59e0b; padding: 6px; background-color: #2b2311; border-radius: 4px;")
        layout.addWidget(self.lbl_disk_warning)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        self.btn_download = QPushButton("Start Download")
        self.btn_download.setObjectName("btnDownload")
        self.btn_download.setDefault(True)
        self.btn_download.clicked.connect(self._on_download)
        btn_layout.addWidget(self.btn_download)
        layout.addLayout(btn_layout)

        self.tabs.addTab(tab_single, "Single Download")

        # ---- TAB 2: Batch Links Import ----
        tab_batch = QWidget()
        b_layout = QVBoxLayout(tab_batch)
        b_layout.setSpacing(10)
        b_layout.setContentsMargins(12, 12, 12, 12)

        b_hdr = QHBoxLayout()
        b_hdr.addWidget(QLabel("Paste multiple URLs, Magnets, or MEGA links (one per line):"))
        b_hdr.addStretch()
        self.btn_load_txt = QPushButton("Load .txt File...")
        self.btn_load_txt.setIcon(get_icon("folder"))
        self.btn_load_txt.clicked.connect(self._load_batch_txt_file)
        b_hdr.addWidget(self.btn_load_txt)
        b_layout.addLayout(b_hdr)

        self.txt_batch_urls = QTextEdit()
        self.txt_batch_urls.setPlaceholderText("https://example.com/file1.zip\nhttps://example.com/file2.mp4\nmagnet:?xt=urn:btih:...")
        self.txt_batch_urls.setMaximumHeight(110)
        self.txt_batch_urls.textChanged.connect(self._refresh_batch_preview)
        b_layout.addWidget(self.txt_batch_urls)

        self.batch_table = QTableWidget()
        self.batch_table.setColumnCount(4)
        self.batch_table.setHorizontalHeaderLabels(["Add", "Link / Filename", "Engine", "Stage 1 Security"])
        self.batch_table.verticalHeader().setVisible(False)
        self.batch_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.batch_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.batch_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.batch_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        b_layout.addWidget(self.batch_table)

        b_btns = QHBoxLayout()
        b_btns.addStretch()
        btn_b_cancel = QPushButton("Cancel")
        btn_b_cancel.clicked.connect(self.reject)
        b_btns.addWidget(btn_b_cancel)
        self.btn_add_batch = QPushButton("Add Checked Links")
        self.btn_add_batch.setObjectName("btnDownload")
        self.btn_add_batch.clicked.connect(self._on_accept_batch)
        b_btns.addWidget(self.btn_add_batch)
        b_layout.addLayout(b_btns)

        self.tabs.addTab(tab_batch, "Batch Links")

    def set_batch_text(self, text: str):
        self.txt_batch_urls.setPlainText(text)
        self.tabs.setCurrentIndex(1)
        self._refresh_batch_preview()

    def _load_batch_txt_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Select URL List (.txt)", "", "Text Files (*.txt);;All Files (*.*)")
        if fp:
            try:
                content = Path(fp).read_text(encoding="utf-8", errors="ignore")
                self.set_batch_text(content)
            except Exception as exc:
                QMessageBox.warning(self, "Read Failed", f"Could not read file:\n{exc}")

    def _refresh_batch_preview(self):
        parsed = parse_batch_links_text(self.txt_batch_urls.toPlainText())
        self._batch_preview_items = []
        self._batch_checkboxes = []
        self.batch_table.setRowCount(len(parsed))

        for row, item in enumerate(parsed):
            gate_eval = self.engine_manager.security_gate.evaluate_pre_download(item["url"], item["filename"])
            verdict = gate_eval.get("verdict", "ALLOW_CLEAN")
            is_crit = (verdict == "BLOCK_CRITICAL")

            chk = QCheckBox()
            chk.setChecked(not is_crit)
            chk.setEnabled(not is_crit)
            self._batch_checkboxes.append(chk)

            chk_wrap = QFrame()
            w_lay = QHBoxLayout(chk_wrap)
            w_lay.addWidget(chk)
            w_lay.setAlignment(Qt.AlignCenter)
            w_lay.setContentsMargins(0, 0, 0, 0)
            self.batch_table.setCellWidget(row, 0, chk_wrap)

            lbl_item = QTableWidgetItem(f"{item['filename']} ({item['url']})")
            self.batch_table.setItem(row, 1, lbl_item)
            self.batch_table.setItem(row, 2, QTableWidgetItem(item["engine_type"]))

            sec_txt = "CRITICAL BLOCKED" if is_crit else ("Warning" if verdict == "ALLOW_WARNING" else "Clean")
            sec_cell = QTableWidgetItem(sec_txt)
            if is_crit:
                sec_cell.setForeground(QColor("#ef4444"))
            elif verdict == "ALLOW_WARNING":
                sec_cell.setForeground(QColor("#f59e0b"))
            else:
                sec_cell.setForeground(QColor("#10b981"))
            self.batch_table.setItem(row, 3, sec_cell)

            item_rec = dict(item)
            item_rec["verdict"] = verdict
            self._batch_preview_items.append(item_rec)

    def _on_accept_batch(self):
        self._refresh_batch_preview()
        dest = self.txt_dest.text().strip() or self.default_dest
        selected = []
        for idx, chk in enumerate(self._batch_checkboxes):
            if chk.isChecked() and idx < len(self._batch_preview_items):
                rec = dict(self._batch_preview_items[idx])
                rec["destination"] = dest
                selected.append(rec)
        if not selected:
            QMessageBox.warning(self, "No Safe Links", "Please paste at least one valid safe link to add.")
            return
        self.batch_results = selected
        self.result_data = None
        self.accept()

    def _is_torrent_input(self, url: str) -> bool:
        clean = (url or "").strip().strip('"').strip("'")
        if not clean:
            return False
        lower = clean.lower()
        if lower.startswith("magnet:"):
            return True
        if lower.endswith(".torrent"):
            return True
        if lower.startswith(("http://", "https://")):
            if urlparse(clean).path.lower().endswith(".torrent"):
                return True
        try:
            if os.path.exists(clean) and lower.endswith(".torrent"):
                return True
        except Exception:
            pass
        return False

    def _stop_probe_worker(self):
        self._probe_timer.stop()
        self._pending_probe_url = None
        if self.probe_worker is not None:
            try:
                self.probe_worker.cancel()
                self.probe_worker.probed.disconnect()
            except Exception:
                pass
            if self.probe_worker.isRunning():
                self.probe_worker.wait(1000)
            self.probe_worker = None

    def _start_pending_probe(self):
        url = self._pending_probe_url
        if not url:
            return
        self._stop_probe_worker()
        self.probe_worker = ProbeWorker(self.engine_manager, url)
        self.probe_worker.probed.connect(self._on_probed)
        self.probe_worker.start()

    def _on_browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Download Folder", self.txt_dest.text())
        if folder:
            self.txt_dest.setText(folder)

    def _on_open_torrent_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Torrent File", "", "Torrent Files (*.torrent);;All Files (*.*)")
        if file_path:
            self.txt_url.setText(file_path)
            self.txt_filename.setText(Path(file_path).name)
            self._evaluate_security_gate()

    def _on_url_changed(self, url):
        try:
            clean_url = (url or "").strip().strip('"').strip("'")
            self._probed_total_bytes = 0
            self.lbl_disk_warning.setVisible(False)
            if not clean_url:
                self._probed_resumable = -1
                self.combo_segments.setEnabled(True)
                self.btn_download.setText("Start Download")
                self.btn_download.setEnabled(True)
                self.lbl_resumable.setText("Resume Capability: Unknown")
                self.lbl_resumable.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")
                self.lbl_security.setText("Stage 1 Security Check: Enter link to evaluate")
                self.lbl_security.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")
                return

            if self._is_torrent_input(clean_url):
                self._stop_probe_worker()
                self._probed_resumable = 1
                self.combo_segments.setEnabled(False)
                self.lbl_resumable.setText("Resume Capability: Yes (BitTorrent Piece Recovery)")
                self.lbl_resumable.setStyleSheet("color: #10b981; padding: 6px; background-color: #112b1c; border-radius: 4px;")
                self.lbl_security.setText("Stage 1 Security: Torrent detected — will open Pre-Download Inspector")
                self.lbl_security.setStyleSheet("color: #00d2ff; padding: 6px; background-color: #0d1a2b; border-radius: 4px;")
                self.btn_download.setText("Inspect Torrent Files...")
                self.btn_download.setEnabled(True)
                return

            if MegaUrlResolver.is_mega_url(clean_url):
                self._stop_probe_worker()
                self._probed_resumable = 1
                self.combo_segments.setEnabled(True)
                self.lbl_resumable.setText("Resume Capability: Yes (MEGA 16-Byte Aligned Offset)")
                self.lbl_resumable.setStyleSheet("color: #10b981; padding: 6px; background-color: #112b1c; border-radius: 4px;")
                self.lbl_security.setText("Stage 1 Security: MEGA.nz encrypted link detected")
                self.lbl_security.setStyleSheet("color: #00d2ff; padding: 6px; background-color: #0d1a2b; border-radius: 4px;")
                self.btn_download.setText("Start Download")
                self.btn_download.setEnabled(True)
                return

            self._probed_resumable = -1
            self.combo_segments.setEnabled(True)
            self.btn_download.setText("Start Download")
            self.btn_download.setEnabled(True)
            self.lbl_resumable.setText("Resume Capability: Checking...")
            self.lbl_resumable.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")

            if clean_url.lower().startswith(("http://", "https://")):
                self._stop_probe_worker()
                self._pending_probe_url = clean_url
                self._probe_timer.start(250)
        except Exception as e:
            logger.exception(f"Error in _on_url_changed: {e}")

    def _on_probed(self, info):
        try:
            if not isinstance(info, dict):
                return
            filename = info.get("filename")
            if filename and filename != "download.bin" and not self.txt_filename.text().strip():
                self.txt_filename.setText(filename)

            self._probed_total_bytes = int(info.get("total_bytes") or 0)
            if self._probed_total_bytes > 0 and hasattr(self.engine_manager, "check_disk_space"):
                disk_res = self.engine_manager.check_disk_space(self.txt_dest.text().strip() or self.default_dest, self._probed_total_bytes)
                if not disk_res["ok"]:
                    self.lbl_disk_warning.setText(disk_res["message"])
                    self.lbl_disk_warning.setVisible(True)
                else:
                    self.lbl_disk_warning.setVisible(False)

            status = info.get("status", 0)
            if 200 <= status < 400 and not info.get("error"):
                if info.get("accept_ranges"):
                    self._probed_resumable = 1
                    self.combo_segments.setEnabled(True)
                    self.lbl_resumable.setText("Resume Capability: Yes (Multi-Segment Range Supported)")
                    self.lbl_resumable.setStyleSheet("color: #10b981; padding: 6px; background-color: #112b1c; border-radius: 4px;")
                else:
                    self._probed_resumable = 0
                    self.combo_segments.setEnabled(False)
                    self.lbl_resumable.setText("Resume Capability: No (Server lacks Range support — Single Stream)")
                    self.lbl_resumable.setStyleSheet("color: #f59e0b; padding: 6px; background-color: #2b2311; border-radius: 4px;")
            else:
                self._probed_resumable = -1
                self.combo_segments.setEnabled(True)
                self.lbl_resumable.setText("Resume Capability: Unknown (Will verify on start)")
                self.lbl_resumable.setStyleSheet("color: #9ca3af; padding: 6px; background-color: #0d0f17; border-radius: 4px;")

            self._evaluate_security_gate()
        except Exception as e:
            logger.exception(f"Error in _on_probed: {e}")

    def _evaluate_security_gate(self):
        try:
            url = self.txt_url.text().strip().strip('"').strip("'")
            filename = self.txt_filename.text().strip()
            if not filename:
                return

            gate_eval = self.engine_manager.security_gate.evaluate_pre_download(url, filename)
            verdict = gate_eval["verdict"]

            if verdict == "BLOCK_CRITICAL":
                self.lbl_security.setText(f"Stage 1 Security Alert: CRITICAL TRAP BLOCKED — {gate_eval.get('threat_name')}")
                self.lbl_security.setStyleSheet("color: #ef4444; font-weight: bold; padding: 6px; background-color: #2b1115; border-radius: 4px;")
                self.btn_download.setEnabled(False)
            elif verdict == "ALLOW_WARNING":
                self.lbl_security.setText(f"Stage 1 Security Notice: Warning — {gate_eval.get('details')}")
                self.lbl_security.setStyleSheet("color: #f59e0b; padding: 6px; background-color: #2b2311; border-radius: 4px;")
                self.btn_download.setEnabled(True)
            else:
                self.lbl_security.setText("Stage 1 Security Check: Clean URL & Filename Structure")
                self.lbl_security.setStyleSheet("color: #10b981; padding: 6px; background-color: #112b1c; border-radius: 4px;")
                self.btn_download.setEnabled(True)
        except Exception as e:
            logger.exception(f"Error evaluating security gate in AddDownloadDialog: {e}")

    def _on_download(self):
        try:
            url = self.txt_url.text().strip().strip('"').strip("'")
            filename = self.txt_filename.text().strip()

            if not url:
                QMessageBox.warning(self, "Invalid Link", "Please enter a valid download link (HTTP, HTTPS, Magnet, MEGA, or .torrent file).")
                return

            is_torrent = self._is_torrent_input(url)
            is_mega = MegaUrlResolver.is_mega_url(url)
            is_http = url.lower().startswith(("http://", "https://"))

            if not (is_torrent or is_mega or is_http):
                QMessageBox.warning(
                    self,
                    "Unsupported Link",
                    "Please enter a valid http://, https://, magnet:?, mega.nz link, or local .torrent file path."
                )
                return

            if not filename:
                if is_torrent:
                    if url.lower().startswith("magnet:"):
                        filename = "torrent_download"
                    else:
                        filename = Path(urlparse(url).path if is_http else url).name or "torrent_download"
                elif is_mega:
                    filename = "MEGA_Download"
                else:
                    leaf = Path(unquote(urlparse(url).path)).name
                    filename = leaf if leaf else "download.bin"

            dest = self.txt_dest.text().strip() or self.default_dest
            if self._probed_total_bytes > 0 and hasattr(self.engine_manager, "check_disk_space"):
                disk_res = self.engine_manager.check_disk_space(dest, self._probed_total_bytes)
                if not disk_res["ok"]:
                    reply = QMessageBox.warning(
                        self,
                        "Insufficient Disk Space",
                        f"{disk_res['message']}\n\nContinue anyway?",
                        QMessageBox.Yes | QMessageBox.No,
                    )
                    if reply != QMessageBox.Yes:
                        return

            seg_text = self.combo_segments.currentText()
            try:
                num_segs = int(seg_text.split()[0])
            except Exception:
                num_segs = 8

            self._stop_probe_worker()

            self.batch_results = []
            self.result_data = {
                "is_torrent": is_torrent,
                "url": url,
                "filename": filename,
                "destination": dest,
                "num_segments": 1 if (not is_torrent and not is_mega and self._probed_resumable == 0) else num_segs,
                "resumable": 1 if (is_torrent or is_mega) else self._probed_resumable,
            }
            logger.info(f"AddDownloadDialog accepted: url={url}, is_torrent={is_torrent}, filename={filename}")
            self.accept()
        except Exception as e:
            logger.exception(f"Failed to start download from AddDownloadDialog: {e}")
            QMessageBox.critical(self, "Download Error", f"Could not start download:\n{str(e)}")

    def reject(self):
        self._stop_probe_worker()
        super().reject()

    def closeEvent(self, event):
        self._stop_probe_worker()
        super().closeEvent(event)
