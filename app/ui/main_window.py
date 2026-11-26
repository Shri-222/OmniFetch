"""
OmniFetch Main Window (PySide6 Native Desktop Shell)
Linear / Fluent inspired dark design with real-time download visibility,
sidebar counts & categories, live search/filter/sorting, collapsible inspector,
drag-and-drop, full keyboard shortcuts, and CyberShield security posture.
"""

import os
import sys
import shutil
import subprocess
import webbrowser
from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QListWidget, QListWidgetItem,
    QTableView, QPushButton, QLabel, QStatusBar,
    QHeaderView, QMessageBox, QMenu, QFrame, QSpacerItem, QSizePolicy,
    QAbstractItemView, QDialog, QProgressBar, QSplitter, QLineEdit, QFormLayout,
    QComboBox, QCheckBox, QInputDialog
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, Slot, QItemSelection, QItemSelectionModel, QSize
from PySide6.QtGui import QAction, QIcon, QCursor, QKeySequence

from .theme import DARK_THEME_QSS
from .download_table import DownloadTableModel, ProgressBarDelegate, format_bytes
from .add_dialog import AddDownloadDialog, parse_batch_links_text
from .torrent_dialog import TorrentDialog
from .proxy_dialog import ProxyDialog
from .grabber_dialog import BatchGrabberDialog
from .speed_graph import SpeedGraphWidget
from .settings_dialog import SettingsDialog
from .inspector_drawer import TaskInspectorDrawer
from .tray import OmniFetchTray
from .icons import get_icon
from ..engines.torrent.file_tree import TorrentFileInspector
from ..engines.mega.resolver import MegaUrlResolver
from ..engines.mega.client import MegaClient
from ..integrations.clipboard_listener import ClipboardListener
from ..integrations.browser_bridge import BrowserHandoffBridge
from ..core.config import get_resource_path
from ..core.engine_manager import EngineManager, classify_file_category
from ..core.scheduler import DownloadScheduler
from ..core.logger import get_logger

logger = get_logger("ui")


class MagnetMetadataWorker(QThread):
    metadata_ready = Signal(object)
    error = Signal(str)
    status_update = Signal(str)

    def __init__(self, engine_manager, magnet_uri, timeout_seconds=60):
        super().__init__()
        self.engine_manager = engine_manager
        self.magnet_uri = magnet_uri
        self.timeout_seconds = timeout_seconds
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            ti = self.engine_manager.fetch_magnet_metadata(
                self.magnet_uri,
                timeout_seconds=self.timeout_seconds,
                cancel_check=lambda: self._cancelled,
                status_callback=lambda msg: self.status_update.emit(msg) if not self._cancelled else None,
            )
            if not self._cancelled:
                self.metadata_ready.emit(ti)
        except InterruptedError:
            pass
        except Exception as e:
            logger.warning(f"MagnetMetadataWorker failed: {e}")
            if not self._cancelled:
                self.error.emit(str(e))


class RefreshAddressDialog(QDialog):
    """Modal dialog allowing expired/broken HTTP downloads to receive a fresh URL or Brave capture."""

    def __init__(self, task: dict, engine_manager: EngineManager, browser_bridge: BrowserHandoffBridge, parent=None):
        super().__init__(parent)
        self.task = task
        self.engine_manager = engine_manager
        self.browser_bridge = browser_bridge
        self.setWindowTitle(f"Refresh Download Address — {task.get('filename', task['id'])}")
        self.resize(580, 290)
        self._init_ui()
        if self.browser_bridge:
            self.browser_bridge.refresh_link_received.connect(self._on_bridge_link_captured)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        info = QLabel(
            f"Replace the expired or rejected URL for <strong>{self.task.get('filename')}</strong>.\n"
            f"All existing partial segments in .staging/{self.task['id']} will be preserved and resumed cleanly."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #9ca3af; font-size: 12px;")
        layout.addWidget(info)

        form = QFormLayout()
        form.setSpacing(8)
        self.txt_old = QLineEdit(str(self.task.get("url") or ""))
        self.txt_old.setReadOnly(True)
        self.txt_new_url = QLineEdit()
        self.txt_new_url.setPlaceholderText("Paste fresh https://... download URL here")
        self.txt_referer = QLineEdit(str(self.task.get("origin_referer") or ""))
        self.txt_referer.setPlaceholderText("Optional Referer URL")
        self.txt_cookie = QLineEdit()
        self.txt_cookie.setPlaceholderText("Optional updated Cookie header")

        form.addRow("Current URL:", self.txt_old)
        form.addRow("Fresh Download URL:", self.txt_new_url)
        form.addRow("Referer (Optional):", self.txt_referer)
        form.addRow("Cookie (Optional):", self.txt_cookie)
        layout.addLayout(form)

        self.lbl_capture_status = QLabel("")
        self.lbl_capture_status.setStyleSheet("color: #00d2ff; font-size: 11px;")
        layout.addWidget(self.lbl_capture_status)

        btn_row = QHBoxLayout()
        self.btn_open_origin = QPushButton("Open Origin Page in Brave")
        self.btn_open_origin.setIcon(get_icon("proxies"))
        self.btn_open_origin.clicked.connect(self._open_origin_in_browser)
        btn_row.addWidget(self.btn_open_origin)
        btn_row.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        self.btn_apply = QPushButton("Validate && Resume")
        self.btn_apply.setObjectName("btnPrimary")
        self.btn_apply.clicked.connect(self._apply_refresh)
        btn_row.addWidget(self.btn_apply)
        layout.addLayout(btn_row)

    def _open_origin_in_browser(self):
        origin = (self.task.get("origin_referer") or self.task.get("url") or "").strip()
        if self.browser_bridge:
            self.browser_bridge.pending_refresh_task_id = self.task["id"]
        self.lbl_capture_status.setText("Waiting for Brave extension to capture the refreshed download link...")
        if origin:
            try:
                webbrowser.open(origin)
            except Exception as exc:
                QMessageBox.warning(self, "Browser Launch Failed", f"Could not open origin page:\n{exc}")

    def _on_bridge_link_captured(self, tid: str, new_url: str, headers: dict):
        if tid == self.task["id"]:
            self.txt_new_url.setText(new_url)
            self.accept()

    def _apply_refresh(self):
        new_url = self.txt_new_url.text().strip()
        if not new_url:
            QMessageBox.warning(self, "Missing URL", "Please enter a fresh download URL or capture it from Brave.")
            return

        custom_headers = {}
        if self.txt_referer.text().strip():
            custom_headers["Referer"] = self.txt_referer.text().strip()
        if self.txt_cookie.text().strip():
            custom_headers["Cookie"] = self.txt_cookie.text().strip()

        res = self.engine_manager.refresh_download_address(self.task["id"], new_url, custom_headers=custom_headers)
        if not res.get("success"):
            probe = res.get("probe") or {}
            reason = res.get("reason", "Validation failed")
            if probe.get("status", 0) in (200, 206):
                reply = QMessageBox.question(
                    self,
                    "Metadata Mismatch",
                    f"{reason}\n\nProceed anyway without clearing partial segments?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply == QMessageBox.Yes:
                    res = self.engine_manager.refresh_download_address(
                        self.task["id"], new_url, custom_headers=custom_headers, force=True
                    )
            if not res.get("success"):
                QMessageBox.critical(self, "Refresh Failed", res.get("reason", reason))
                return

        if self.browser_bridge and self.browser_bridge.pending_refresh_task_id == self.task["id"]:
            self.browser_bridge.pending_refresh_task_id = None
        self.engine_manager.resume_download(self.task["id"])
        self.accept()

    def closeEvent(self, event):
        if self.browser_bridge and self.browser_bridge.pending_refresh_task_id == self.task["id"]:
            self.browser_bridge.pending_refresh_task_id = None
        super().closeEvent(event)

    def reject(self):
        if self.browser_bridge and self.browser_bridge.pending_refresh_task_id == self.task["id"]:
            self.browser_bridge.pending_refresh_task_id = None
        super().reject()


class PostDownloadCountdownDialog(QDialog):
    """Mandatory 30-second cancellable countdown before executing Sleep or Shutdown."""

    def __init__(self, action_name: str, countdown_seconds: int = 30, parent=None):
        super().__init__(parent)
        self.action_name = action_name
        self.seconds_left = max(1, int(countdown_seconds))
        self.setWindowTitle(f"OmniFetch — Scheduled {action_name}")
        self.setModal(True)
        self.setFixedWidth(440)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        self.lbl_msg = QLabel(f"All downloads completed.\n{action_name} in {self.seconds_left} seconds...")
        self.lbl_msg.setStyleSheet("font-size: 13px; font-weight: 600; color: #f59e0b;")
        layout.addWidget(self.lbl_msg)

        self.pbar = QProgressBar()
        self.pbar.setRange(0, self.seconds_left)
        self.pbar.setValue(self.seconds_left)
        layout.addWidget(self.pbar)

        row = QHBoxLayout()
        row.addStretch()
        btn_cancel = QPushButton("Cancel Action")
        btn_cancel.setObjectName("btnPrimary")
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)
        layout.addLayout(row)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self):
        self.seconds_left -= 1
        self.pbar.setValue(max(0, self.seconds_left))
        if self.seconds_left <= 0:
            self._timer.stop()
            self.accept()
        else:
            self.lbl_msg.setText(f"All downloads completed.\n{self.action_name} in {self.seconds_left} seconds...")

    def reject(self):
        self._timer.stop()
        super().reject()

    def closeEvent(self, event):
        self._timer.stop()
        super().closeEvent(event)


class SmartDeleteDialog(QDialog):
    """Confirmation dialog with opt-in disk file removal (safe unchecked default)."""

    def __init__(self, tasks: list[dict], parent=None):
        super().__init__(parent)
        count = len(tasks)
        self.setWindowTitle("Delete Task" if count == 1 else f"Delete {count} Selected Tasks")
        self.setFixedWidth(440)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        if count == 1:
            msg = f"Remove task <strong>{tasks[0].get('filename')}</strong> from the list?"
        else:
            msg = f"Remove <strong>{count} selected tasks</strong> from the list?"
        lbl = QLabel(msg)
        lbl.setWordWrap(True)
        layout.addWidget(lbl)

        self.chk_delete_files = QCheckBox("Also permanently delete downloaded / staged files from disk")
        self.chk_delete_files.setChecked(False)
        layout.addWidget(self.chk_delete_files)

        row = QHBoxLayout()
        row.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)
        btn_ok = QPushButton("Delete")
        btn_ok.setStyleSheet("background-color: #ef4444; border-color: #dc2626; color: #fff; font-weight: 600;")
        btn_ok.clicked.connect(self.accept)
        row.addWidget(btn_ok)
        layout.addLayout(row)


class MainWindow(QMainWindow):
    _STATUS_FILTERS = [
        ("All Downloads", "All", "app"),
        ("Downloading", "Downloading", "resume"),
        ("Completed", "Completed", "check"),
        ("Paused", "Paused", "pause"),
        ("Failed / Expired", "Failed", "warning"),
        ("Security Vault", "Security Vault", "shield"),
    ]
    _CATEGORY_FILTERS = [
        ("Videos", "video"),
        ("Archives", "archive"),
        ("Programs", "program"),
        ("Documents", "document"),
        ("Images", "image"),
        ("Torrents", "torrent"),
        ("MEGA", "mega"),
    ]

    def __init__(self, engine_manager: EngineManager):
        super().__init__()
        self.engine_manager = engine_manager
        self.current_filter = "All"
        self.current_category = None
        self.current_engine_filter = "ALL"
        self._is_force_quitting = False
        self.setAcceptDrops(True)
        self.init_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_tasks_from_db)
        self.refresh_timer.start(1000)

        # Smart Batch Clipboard Grabber (0% polling waste via QClipboard signals)
        self.clipboard_listener = ClipboardListener(self, initial_enabled=True)
        self.clipboard_listener.links_detected.connect(self._on_clipboard_links_detected)
        self.clipboard_listener.start()

        # System Tray Integration
        self.tray = OmniFetchTray(self, self.engine_manager, self.clipboard_listener)
        self.tray.show()

        # Brave Browser Handoff Bridge (authenticated 127.0.0.1 service)
        self.browser_bridge = BrowserHandoffBridge(self.engine_manager.config, self.engine_manager, self)
        self.browser_bridge.magnet_inspector_enabled = True
        self.browser_bridge.start()
        self.browser_bridge.download_received.connect(self._on_bridge_download_received, Qt.QueuedConnection)
        self.browser_bridge.magnet_handoff_requested.connect(self._on_bridge_magnet_handoff, Qt.QueuedConnection)
        self.browser_bridge.refresh_link_received.connect(self._on_bridge_refresh_received, Qt.QueuedConnection)

        # Daily Queue Scheduler timer
        self.scheduler = DownloadScheduler()
        self.schedule_timer = QTimer(self)
        self.schedule_timer.timeout.connect(self._on_schedule_tick)
        self.schedule_timer.start(15000)

    def init_ui(self):
        self.setWindowTitle("OmniFetch — Native Desktop Download Manager")
        self.resize(1220, 760)
        self.setMinimumSize(920, 560)
        self.setStyleSheet(DARK_THEME_QSS)

        ico_file = get_resource_path("app/assets/omnifetch.ico")
        if ico_file.exists():
            self.setWindowIcon(QIcon(str(ico_file)))
        else:
            self.setWindowIcon(get_icon("app", size=32))

        root_widget = QWidget()
        self.setCentralWidget(root_widget)
        root_layout = QHBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Left Sidebar (Status Filters + Categories + Pinned Proxies/Settings)
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebarContainer")
        sidebar_widget.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(0, 0, 0, 12)
        sidebar_layout.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setIconSize(QSize(16, 16))
        self.sidebar.setMaximumHeight(270)
        for label, _, icon_name in self._STATUS_FILTERS:
            item = QListWidgetItem(get_icon(icon_name, color="#9ca3af", size=16), f"{label} (0)")
            self.sidebar.addItem(item)
        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._on_filter_changed)
        sidebar_layout.addWidget(self.sidebar)

        cat_sep = QFrame()
        cat_sep.setFrameShape(QFrame.HLine)
        cat_sep.setFrameShadow(QFrame.Plain)
        cat_sep.setObjectName("sidebarDivider")
        sidebar_layout.addWidget(cat_sep)

        cat_hdr = QLabel("SMART CATEGORIES")
        cat_hdr.setObjectName("sidebarCatHeader")
        sidebar_layout.addWidget(cat_hdr)

        self.category_sidebar = QListWidget()
        self.category_sidebar.setObjectName("sidebar")
        self.category_sidebar.setIconSize(QSize(15, 15))
        for cat_name, icon_name in self._CATEGORY_FILTERS:
            c_item = QListWidgetItem(get_icon(icon_name, color="#9ca3af", size=15), f"{cat_name} (0)")
            self.category_sidebar.addItem(c_item)
        self.category_sidebar.itemClicked.connect(self._on_category_clicked)
        sidebar_layout.addWidget(self.category_sidebar, 1)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Plain)
        divider.setObjectName("sidebarDivider")
        sidebar_layout.addWidget(divider)

        bottom_actions = QWidget()
        bottom_actions_layout = QVBoxLayout(bottom_actions)
        bottom_actions_layout.setContentsMargins(8, 8, 8, 0)
        bottom_actions_layout.setSpacing(6)

        self.btn_proxies = QPushButton("Proxies")
        self.btn_proxies.setObjectName("btnSidebar")
        self.btn_proxies.setIcon(get_icon("proxies"))
        self.btn_proxies.setToolTip("Configure HTTP/HTTPS proxy rotation & test latencies")
        self.btn_proxies.clicked.connect(self._show_proxy_dialog)
        bottom_actions_layout.addWidget(self.btn_proxies)

        self.btn_settings = QPushButton("Settings")
        self.btn_settings.setObjectName("btnSidebar")
        self.btn_settings.setIcon(get_icon("settings"))
        self.btn_settings.setToolTip("Settings (Ctrl+,)")
        self.btn_settings.clicked.connect(self._show_settings_dialog)
        bottom_actions_layout.addWidget(self.btn_settings)

        sidebar_layout.addWidget(bottom_actions)
        root_layout.addWidget(sidebar_widget)

        # 2. Right Content Area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Top Action Header Bar
        header_bar = QWidget()
        header_bar.setObjectName("headerBar")
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(8)

        btn_new = QPushButton("New Download")
        btn_new.setObjectName("btnAccent")
        btn_new.setIcon(get_icon("add", color="#0d0f17"))
        btn_new.setToolTip("New Download (Ctrl+N)")
        btn_new.clicked.connect(self._show_add_dialog)
        header_layout.addWidget(btn_new)

        header_layout.addWidget(self._create_header_separator())

        btn_pause = QPushButton("Pause")
        btn_pause.setIcon(get_icon("pause"))
        btn_pause.clicked.connect(self._pause_selected)
        header_layout.addWidget(btn_pause)

        btn_resume = QPushButton("Resume")
        btn_resume.setIcon(get_icon("resume"))
        btn_resume.clicked.connect(self._resume_selected)
        header_layout.addWidget(btn_resume)

        btn_delete = QPushButton("Delete")
        btn_delete.setIcon(get_icon("delete"))
        btn_delete.clicked.connect(self._delete_selected)
        header_layout.addWidget(btn_delete)

        header_layout.addWidget(self._create_header_separator())

        btn_open_folder = QPushButton("Open Folder")
        btn_open_folder.setIcon(get_icon("folder"))
        btn_open_folder.clicked.connect(self._open_selected_folder)
        header_layout.addWidget(btn_open_folder)

        header_layout.addWidget(self._create_header_separator())

        self.btn_grabber = QPushButton("Grabber: ON")
        self.btn_grabber.setIcon(get_icon("clipboard"))
        self.btn_grabber.clicked.connect(self._toggle_clipboard_grabber)
        header_layout.addWidget(self.btn_grabber)

        self.btn_inspector = QPushButton("Inspector")
        self.btn_inspector.setCheckable(True)
        self.btn_inspector.setChecked(False)
        self.btn_inspector.setIcon(get_icon("activity"))
        self.btn_inspector.setToolTip("Toggle collapsible bottom task inspector drawer (Ctrl+I)")
        self.btn_inspector.clicked.connect(self._toggle_inspector)
        header_layout.addWidget(self.btn_inspector)

        header_layout.addWidget(self._create_header_separator())

        self.combo_post_action = QComboBox()
        for label, val in (
            ("After Done: None", "None"),
            ("After Done: Notify", "Notify Only"),
            ("After Done: Sleep PC", "Sleep PC"),
            ("After Done: Shutdown PC", "Shutdown PC"),
        ):
            self.combo_post_action.addItem(label, val)
        p_idx = self.combo_post_action.findData(getattr(self.engine_manager.config, "post_download_action", "None"))
        self.combo_post_action.setCurrentIndex(max(0, p_idx))
        self.combo_post_action.setToolTip("Action executed once all queued/active downloads finish")
        self.combo_post_action.currentIndexChanged.connect(self._on_post_action_changed)
        header_layout.addWidget(self.combo_post_action)

        header_layout.addStretch()
        content_layout.addWidget(header_bar)

        # Search + Engine Filter Strip
        filter_bar = QWidget()
        filter_bar.setObjectName("filterBar")
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(12, 6, 12, 6)
        filter_layout.setSpacing(8)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search filename, URL, or status... (Ctrl+F)")
        self.txt_search.setClearButtonEnabled(True)
        self.txt_search.setMaximumWidth(340)
        self.txt_search.setStyleSheet("padding: 5px 10px; font-size: 12px;")
        self.txt_search.textChanged.connect(self._refresh_tasks_from_db)
        filter_layout.addWidget(self.txt_search)

        self.engine_pills = {}
        for pill_lbl, eng_key in (("All", "ALL"), ("HTTP", "HTTP"), ("Torrent", "TORRENT"), ("MEGA", "MEGA")):
            btn = QPushButton(pill_lbl)
            btn.setObjectName("pillBtn")
            btn.setProperty("active", eng_key == "ALL")
            btn.clicked.connect(lambda checked=False, k=eng_key: self.set_engine_filter(k))
            self.engine_pills[eng_key] = btn
            filter_layout.addWidget(btn)

        filter_layout.addStretch()
        self.lbl_view_summary = QLabel("")
        self.lbl_view_summary.setStyleSheet("color: #6b7280; font-size: 11px;")
        filter_layout.addWidget(self.lbl_view_summary)
        content_layout.addWidget(filter_bar)

        # Central Download Table
        self.table = QTableView()
        self.table_model = DownloadTableModel()
        self.table.setModel(self.table_model)
        delegate = ProgressBarDelegate(self.table)
        self.table.setItemDelegateForColumn(2, delegate)
        self.table.setItemDelegateForColumn(7, delegate)
        self.table.setItemDelegateForColumn(8, delegate)
        self.table.setIconSize(QSize(16, 16))
        self.table.verticalHeader().setDefaultSectionSize(34)

        default_widths = [250, 115, 120, 95, 75, 85, 75, 190, 120]
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(55)
        saved_widths = self.engine_manager.config.column_widths or {}
        for i in range(self.table_model.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
            w = saved_widths.get(str(i), default_widths[i] if i < len(default_widths) else 100)
            self.table.setColumnWidth(i, int(w) if isinstance(w, (int, float)) and w >= 55 else default_widths[i])

        self.table.setSortingEnabled(True)
        header.setSortIndicator(-1, Qt.DescendingOrder)

        self._col_save_timer = QTimer(self)
        self._col_save_timer.setSingleShot(True)
        self._col_save_timer.timeout.connect(self._save_column_widths)
        header.sectionResized.connect(self._on_column_resized)
        header.sectionHandleDoubleClicked.connect(self._on_header_double_clicked)

        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(self._on_table_double_clicked)

        # Empty-state overlay inside table viewport (transparent to mouse events)
        empty_lay = QVBoxLayout(self.table.viewport())
        self.lbl_empty_state = QLabel("Drop a link or .torrent here, or press Ctrl+N to add a download")
        self.lbl_empty_state.setAlignment(Qt.AlignCenter)
        self.lbl_empty_state.setStyleSheet("color: #6b7280; font-size: 13px; background: transparent;")
        self.lbl_empty_state.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        empty_lay.addWidget(self.lbl_empty_state)

        self.table.selectionModel().selectionChanged.connect(self._update_inspector_for_selection)

        # Collapsible Splitter holding Table (top) + Per-Task Inspector Drawer (bottom)
        self.inspector_drawer = TaskInspectorDrawer(self)
        self.inspector_drawer.setVisible(False)
        self.inspector_drawer.close_requested.connect(lambda: self._set_inspector_visible(False))

        self.vertical_splitter = QSplitter(Qt.Vertical, self)
        self.vertical_splitter.addWidget(self.table)
        self.vertical_splitter.addWidget(self.inspector_drawer)
        self.vertical_splitter.setStretchFactor(0, 3)
        self.vertical_splitter.setStretchFactor(1, 2)
        content_layout.addWidget(self.vertical_splitter)

        # Live 60-second Native Speed Graph
        self.speed_graph = SpeedGraphWidget(self)
        content_layout.addWidget(self.speed_graph)

        root_layout.addWidget(content_widget)

        # Upgraded Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.lbl_active = QLabel("Active: 0 | Queued: 0")
        self.lbl_speed = QLabel("Speed: 0 B/s")
        self.btn_speed_cap = QPushButton("Cap: Unlimited")
        self.btn_speed_cap.setObjectName("statusPillBtn")
        self.btn_speed_cap.setToolTip("Click to adjust global speed limit")
        self.btn_speed_cap.clicked.connect(self._quick_edit_speed_cap)

        self.lbl_disk_free = QLabel("Free: --")
        self.btn_toggle_graph = QPushButton("Hide Graph")
        self.btn_toggle_graph.setObjectName("statusPillBtn")
        self.btn_toggle_graph.clicked.connect(self._toggle_speed_graph)

        self.lbl_security_status = QLabel("CyberShield Gate: Active")
        self.lbl_security_status.setStyleSheet("color: #10b981; font-weight: bold;")

        self.status_bar.addWidget(self.lbl_active)
        self.status_bar.addWidget(self.lbl_speed)
        self.status_bar.addWidget(self.btn_speed_cap)
        self.status_bar.addWidget(self.lbl_disk_free, 1)
        self.status_bar.addPermanentWidget(self.btn_toggle_graph)
        self.status_bar.addPermanentWidget(self.lbl_security_status)

        # Keyboard Shortcuts
        self._init_shortcuts()

        # Wire Engine Signals safely across threads via Qt.QueuedConnection
        self.engine_manager.task_added.connect(self._on_engine_tasks_changed, Qt.QueuedConnection)
        self.engine_manager.tasks_changed.connect(self._on_engine_tasks_changed, Qt.QueuedConnection)
        self.engine_manager.task_progress.connect(self._on_task_progress, Qt.QueuedConnection)
        self.engine_manager.task_status_changed.connect(self._on_task_status_changed, Qt.QueuedConnection)
        self.engine_manager.task_completed.connect(self._on_task_completed, Qt.QueuedConnection)
        self.engine_manager.task_failed.connect(self._on_task_failed, Qt.QueuedConnection)

        self._refresh_tasks_from_db()

    def _init_shortcuts(self):
        self.settings_shortcut = QAction(self)
        self.settings_shortcut.setShortcut(QKeySequence("Ctrl+,"))
        self.settings_shortcut.triggered.connect(self._show_settings_dialog)
        self.addAction(self.settings_shortcut)

        self.new_shortcut = QAction(self)
        self.new_shortcut.setShortcut(QKeySequence("Ctrl+N"))
        self.new_shortcut.triggered.connect(self._show_add_dialog)
        self.addAction(self.new_shortcut)

        self.search_shortcut = QAction(self)
        self.search_shortcut.setShortcut(QKeySequence("Ctrl+F"))
        self.search_shortcut.triggered.connect(lambda: self.txt_search.setFocus())
        self.addAction(self.search_shortcut)

        self.inspector_shortcut = QAction(self)
        self.inspector_shortcut.setShortcut(QKeySequence("Ctrl+I"))
        self.inspector_shortcut.triggered.connect(self._toggle_inspector)
        self.addAction(self.inspector_shortcut)

        self.delete_shortcut = QAction("Delete Selected", self.table)
        self.delete_shortcut.setShortcut(QKeySequence(Qt.Key_Delete))
        self.delete_shortcut.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.delete_shortcut.triggered.connect(self._delete_selected)
        self.table.addAction(self.delete_shortcut)

        self.space_shortcut = QAction("Toggle Pause/Resume", self.table)
        self.space_shortcut.setShortcut(QKeySequence(Qt.Key_Space))
        self.space_shortcut.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.space_shortcut.triggered.connect(self._toggle_pause_resume_selected)
        self.table.addAction(self.space_shortcut)

        self.enter_shortcut = QAction("Open Selected Completed", self.table)
        self.enter_shortcut.setShortcut(QKeySequence(Qt.Key_Return))
        self.enter_shortcut.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.enter_shortcut.triggered.connect(self._open_selected_file)
        self.table.addAction(self.enter_shortcut)

    # Drag & Drop Support
    def dragEnterEvent(self, event):
        md = event.mimeData()
        if md and (md.hasUrls() or md.hasText()):
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dropEvent(self, event):
        md = event.mimeData()
        if not md:
            return
        if md.hasUrls():
            for qurl in md.urls():
                local = qurl.toLocalFile()
                if local and local.lower().endswith(".torrent"):
                    self._handle_torrent_add({"url": local, "destination": self.engine_manager.config.download_dir})
                elif local and local.lower().endswith(".txt"):
                    try:
                        txt = Path(local).read_text(encoding="utf-8", errors="ignore")
                        dlg = AddDownloadDialog(self.engine_manager, self.engine_manager.config.download_dir, self)
                        dlg.set_batch_text(txt)
                        if dlg.exec() and dlg.batch_results:
                            self._add_batch_items(dlg.batch_results)
                    except Exception:
                        pass
                else:
                    s = qurl.toString().strip()
                    if s:
                        self.handle_external_link(s)
            event.acceptProposedAction()
            return
        if md.hasText():
            txt = md.text().strip()
            links = parse_batch_links_text(txt)
            if len(links) > 1:
                dlg = AddDownloadDialog(self.engine_manager, self.engine_manager.config.download_dir, self)
                dlg.set_batch_text(txt)
                if dlg.exec() and dlg.batch_results:
                    self._add_batch_items(dlg.batch_results)
            elif len(links) == 1:
                self.handle_external_link(links[0]["url"])
            event.acceptProposedAction()

    @Slot()
    @Slot(str)
    def _on_engine_tasks_changed(self, *_args):
        self._refresh_tasks_from_db()

    @Slot(str, str)
    def _on_bridge_download_received(self, url: str, task_id: str):
        self._refresh_tasks_from_db()

    @Slot(str, str, dict)
    def _on_bridge_refresh_received(self, task_id: str, new_url: str, headers: dict):
        self._refresh_tasks_from_db()

    def _refresh_table(self):
        self._refresh_tasks_from_db()

    def _on_column_resized(self, logical_index, old_size, new_size):
        if not hasattr(self.engine_manager.config, "column_widths") or not isinstance(self.engine_manager.config.column_widths, dict):
            self.engine_manager.config.column_widths = {}
        self.engine_manager.config.column_widths[str(logical_index)] = int(new_size)
        self._col_save_timer.start(300)

    def _on_header_double_clicked(self, logical_index):
        self.table.resizeColumnToContents(logical_index)
        w = max(55, self.table.columnWidth(logical_index))
        self.table.setColumnWidth(logical_index, w)
        self._on_column_resized(logical_index, 0, w)

    def _save_column_widths(self):
        try:
            self.engine_manager.config.save()
        except Exception:
            pass

    def _on_filter_changed(self, row):
        if 0 <= row < len(self._STATUS_FILTERS):
            self.current_filter = self._STATUS_FILTERS[row][1]
        else:
            self.current_filter = "All"
        self._refresh_tasks_from_db()

    def _on_category_clicked(self, item):
        row = self.category_sidebar.row(item)
        if 0 <= row < len(self._CATEGORY_FILTERS):
            cat_name = self._CATEGORY_FILTERS[row][0]
            if self.current_category == cat_name:
                self.current_category = None
                self.category_sidebar.clearSelection()
                self.category_sidebar.setCurrentRow(-1)
            else:
                self.current_category = cat_name
        self._refresh_tasks_from_db()

    def set_category_filter(self, category: str | None):
        self.current_category = category
        self._refresh_tasks_from_db()

    def set_engine_filter(self, engine_key: str):
        self.current_engine_filter = (engine_key or "ALL").upper()
        for k, btn in self.engine_pills.items():
            btn.setProperty("active", k == self.current_engine_filter)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self._refresh_tasks_from_db()

    def _matches_status_filter(self, t: dict, filt: str) -> bool:
        st = t.get("status")
        if filt == "All":
            return True
        if filt == "Downloading":
            return st in ("DOWNLOADING", "QUEUED", "STAGED", "SCANNING")
        if filt == "Completed":
            return st == "COMPLETED"
        if filt == "Paused":
            return st in ("PAUSED", "QUEUED")
        if filt == "Failed":
            return st in ("FAILED", "LINK EXPIRED")
        if filt == "Security Vault":
            return (
                st == "QUARANTINED"
                or t.get("security_status") in ("CRITICAL", "WARNING")
                or str(t.get("threat_details") or "").startswith("SCAN_ERROR:")
            )
        return True

    def _matches_category_filter(self, t: dict, category: str | None) -> bool:
        if not category:
            return True
        eng = (t.get("engine_type") or "HTTP").upper()
        if category == "Torrents":
            return eng == "TORRENT"
        if category == "MEGA":
            return eng == "MEGA"
        return classify_file_category(t.get("filename"), eng) == category

    def _refresh_tasks_from_db(self):
        all_tasks = self.engine_manager.db.get_all_tasks()
        filtered = []

        active_count = 0
        queued_count = 0
        total_speed = 0.0
        status_counts = {key: 0 for _, key, _ in self._STATUS_FILTERS}
        cat_counts = {name: 0 for name, _ in self._CATEGORY_FILTERS}

        search_q = self.txt_search.text().strip().lower() if hasattr(self, "txt_search") else ""

        for t in all_tasks:
            st = t.get("status")
            eng = (t.get("engine_type") or "HTTP").upper()
            if st == "DOWNLOADING":
                active_count += 1
                total_speed += t.get("speed_bps", 0.0)
            elif st == "QUEUED":
                queued_count += 1

            for _, key, _ in self._STATUS_FILTERS:
                if self._matches_status_filter(t, key):
                    status_counts[key] += 1
            for cname, _ in self._CATEGORY_FILTERS:
                if self._matches_category_filter(t, cname):
                    cat_counts[cname] += 1

            if not self._matches_status_filter(t, self.current_filter):
                continue
            if not self._matches_category_filter(t, self.current_category):
                continue
            if self.current_engine_filter != "ALL" and eng != self.current_engine_filter:
                continue
            if search_q:
                hay = f"{t.get('filename', '')} {t.get('url', '')} {st or ''}".lower()
                if search_q not in hay:
                    continue
            filtered.append(t)

        # Update sidebar live count labels
        for idx, (label, key, _) in enumerate(self._STATUS_FILTERS):
            it = self.sidebar.item(idx)
            if it:
                it.setText(f"{label} ({status_counts[key]})")
        if hasattr(self, "category_sidebar"):
            for idx, (cname, _) in enumerate(self._CATEGORY_FILTERS):
                it = self.category_sidebar.item(idx)
                if it:
                    it.setText(f"{cname} ({cat_counts[cname]})")

        if hasattr(self, "btn_proxies"):
            p_entries = getattr(self.engine_manager.proxy_pool, "entries", []) or []
            if p_entries:
                healthy_cnt = sum(1 for e in p_entries if getattr(e, "is_healthy", True))
                self.btn_proxies.setText(f"Proxies ({healthy_cnt})")
            else:
                self.btn_proxies.setText("Proxies")

        # Preserve selection across structural updates
        sel_model = self.table.selectionModel()
        selected_ids = set()
        current_id = None
        if sel_model:
            for idx in sel_model.selectedRows():
                r = idx.row()
                if 0 <= r < len(self.table_model.tasks):
                    selected_ids.add(self.table_model.tasks[r].get("id"))
            curr_idx = sel_model.currentIndex()
            if curr_idx.isValid() and 0 <= curr_idx.row() < len(self.table_model.tasks):
                current_id = self.table_model.tasks[curr_idx.row()].get("id")

        self.table_model.update_tasks(filtered)

        if sel_model and selected_ids:
            current_selected = {
                self.table_model.tasks[idx.row()].get("id")
                for idx in sel_model.selectedRows()
                if 0 <= idx.row() < len(self.table_model.tasks)
            }
            if current_selected != selected_ids:
                selection = QItemSelection()
                last_col = self.table_model.columnCount() - 1
                for r, t in enumerate(self.table_model.tasks):
                    tid = t.get("id")
                    if tid in selected_ids:
                        selection.select(self.table_model.index(r, 0), self.table_model.index(r, last_col))
                    if tid == current_id:
                        sel_model.setCurrentIndex(
                            self.table_model.index(r, 0),
                            QItemSelectionModel.SelectionFlag.NoUpdate
                        )
                if not selection.isEmpty():
                    sel_model.select(
                        selection,
                        QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows
                    )

        if hasattr(self, "lbl_empty_state"):
            self.lbl_empty_state.setVisible(len(filtered) == 0)
        if hasattr(self, "lbl_view_summary"):
            self.lbl_view_summary.setText(f"{len(filtered)} of {len(all_tasks)} tasks")

        self.lbl_active.setText(f"Active: {active_count} | Queued: {queued_count}")
        self.lbl_speed.setText(f"Speed: {format_bytes(total_speed)}/s")
        cap_kbs = int(getattr(self.engine_manager.config, "speed_limit_kbs", 0) or 0)
        if hasattr(self, "btn_speed_cap"):
            self.btn_speed_cap.setText("Cap: Unlimited" if cap_kbs <= 0 else f"Cap: {format_bytes(cap_kbs * 1024)}/s")
        self._update_disk_free_label()

        self.speed_graph.update_speeds(total_speed, 0.0)
        if hasattr(self, "inspector_drawer") and self.inspector_drawer.isVisible():
            self._update_inspector_for_selection()

    def _update_disk_free_label(self):
        if not hasattr(self, "lbl_disk_free"):
            return
        try:
            dest = Path(self.engine_manager.config.download_dir)
            probe = dest
            while not probe.exists() and probe.parent != probe:
                probe = probe.parent
            free_b = shutil.disk_usage(str(probe)).free
            self.lbl_disk_free.setText(f"Free: {format_bytes(free_b)}")
        except Exception:
            self.lbl_disk_free.setText("Free: --")

    def _quick_edit_speed_cap(self):
        cur = int(getattr(self.engine_manager.config, "speed_limit_kbs", 0) or 0)
        val, ok = QInputDialog.getInt(
            self,
            "Global Speed Cap",
            "Max download speed in KB/s (0 = Unlimited):",
            cur,
            0,
            1000000,
            256,
        )
        if ok:
            self.engine_manager.set_global_speed_limit(val)
            self._refresh_tasks_from_db()

    def _toggle_speed_graph(self):
        vis = not self.speed_graph.isVisible()
        self.speed_graph.setVisible(vis)
        self.btn_toggle_graph.setText("Hide Graph" if vis else "Show Graph")

    def _toggle_inspector(self):
        self._set_inspector_visible(not self.inspector_drawer.isVisible())

    def _set_inspector_visible(self, visible: bool):
        self.inspector_drawer.setVisible(visible)
        if hasattr(self, "btn_inspector"):
            self.btn_inspector.setChecked(visible)
        if visible:
            self._update_inspector_for_selection()

    def _update_inspector_for_selection(self, *_args):
        if not hasattr(self, "inspector_drawer") or not self.inspector_drawer.isVisible():
            return
        task = self._get_selected_task()
        if task:
            fresh = self.engine_manager.db.get_task(task["id"]) or task
            self.inspector_drawer.update_for_task(fresh, self.engine_manager)
        else:
            self.inspector_drawer.update_for_task(None, self.engine_manager)

    @Slot(str, str)
    def _on_bridge_magnet_handoff(self, magnet_url: str, filename: str):
        self.showNormal()
        self.activateWindow()
        self.raise_()
        self._handle_torrent_add({"url": magnet_url, "destination": self.engine_manager.config.download_dir})

    def _create_header_separator(self):
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFrameShadow(QFrame.Plain)
        sep.setObjectName("headerSeparator")
        return sep

    def _show_settings_dialog(self):
        dlg = SettingsDialog(
            self.engine_manager.config,
            self,
            engine_manager=self.engine_manager,
            browser_bridge=self.browser_bridge,
        )
        if dlg.exec():
            speed_limit = self.engine_manager.config.speed_limit_kbs
            self.engine_manager.set_global_speed_limit(speed_limit)
            self.engine_manager.apply_torrent_settings()
            if hasattr(self, "combo_post_action"):
                idx = self.combo_post_action.findData(self.engine_manager.config.post_download_action)
                if idx >= 0:
                    self.combo_post_action.blockSignals(True)
                    self.combo_post_action.setCurrentIndex(idx)
                    self.combo_post_action.blockSignals(False)
            self.scheduler.reset()
            self._on_schedule_tick()
            self._refresh_tasks_from_db()

    def _on_post_action_changed(self):
        val = self.combo_post_action.currentData() or "None"
        self.engine_manager.config.post_download_action = val
        try:
            self.engine_manager.config.save()
        except Exception:
            pass

    def _on_schedule_tick(self):
        try:
            res = self.scheduler.evaluate_tick(self.engine_manager, self.engine_manager.config)
            if res:
                self._refresh_tasks_from_db()
        except Exception as exc:
            logger.debug(f"Schedule tick skipped: {exc}")

    def _toggle_clipboard_grabber(self):
        enabled = self.clipboard_listener.toggle()
        self.btn_grabber.setText(f"Grabber: {'ON' if enabled else 'OFF'}")

    def _show_proxy_dialog(self):
        dlg = ProxyDialog(self.engine_manager.proxy_pool, self, config=self.engine_manager.config)
        if dlg.exec():
            self._refresh_tasks_from_db()

    def _add_batch_items(self, items: list[dict]):
        for item in items:
            eng = item.get("engine_type")
            dest = item.get("destination", self.engine_manager.config.download_dir)
            if eng == "TORRENT":
                self._handle_torrent_add({"url": item["url"], "destination": dest})
            elif eng == "MEGA":
                self._handle_mega_add({"url": item["url"], "destination": dest})
            else:
                task_id = self.engine_manager.add_download(
                    url=item["url"],
                    filename=item.get("filename"),
                    destination=dest,
                )
                self.engine_manager.start_download(task_id)
        self._refresh_tasks_from_db()

    def _on_clipboard_links_detected(self, links):
        dlg = BatchGrabberDialog(links, self.engine_manager.security_gate, self)
        if dlg.exec():
            self._add_batch_items(dlg.selected_links)

    def _show_add_dialog(self):
        dlg = AddDownloadDialog(self.engine_manager, self.engine_manager.config.download_dir, self)
        if dlg.exec():
            try:
                if dlg.batch_results:
                    self._add_batch_items(dlg.batch_results)
                    return
                data = dlg.result_data
                if not data:
                    return
                url = data.get("url", "")
                if data.get("is_torrent"):
                    self._handle_torrent_add(data)
                elif MegaUrlResolver.is_mega_url(url):
                    self._handle_mega_add(data)
                else:
                    task_id = self.engine_manager.add_download(
                        url=data["url"],
                        filename=data["filename"],
                        destination=data["destination"],
                        num_segments=data["num_segments"],
                        resumable=data.get("resumable", -1)
                    )
                    self.engine_manager.start_download(task_id)
                    self._refresh_tasks_from_db()
            except Exception as e:
                logger.exception(f"Failed starting download from AddDownloadDialog: {e}")
                QMessageBox.critical(self, "Download Error", f"Failed to start download:\n{str(e)}")

    def _handle_mega_add(self, data):
        url = data["url"]
        dest = data.get("destination", self.engine_manager.config.download_dir)
        parsed = MegaUrlResolver.parse_url(url)
        if not parsed:
            QMessageBox.warning(self, "Invalid MEGA Link", f"Could not parse MEGA.nz URL:\n{url}")
            return

        if parsed["type"] == "folder":
            import asyncio
            client = MegaClient(self.engine_manager.proxy_pool)
            try:
                nodes = asyncio.run(client.get_folder_nodes(parsed["id"], parsed["key"]))
                tdlg = TorrentDialog(f"MEGA: {parsed['id']}", nodes, dest, self)
                if tdlg.exec():
                    t_res = tdlg.result_data
                    selected = [f["index"] for f in t_res.get("files", []) if f.get("checked")]
                    self.engine_manager.add_mega_download(
                        url=url,
                        destination=t_res["destination"],
                        selected_indices=selected
                    )
                    self._refresh_tasks_from_db()
            except Exception as e:
                logger.exception(f"MEGA folder error: {e}")
                QMessageBox.critical(self, "MEGA Error", f"Failed to inspect MEGA folder:\n{str(e)}")
        else:
            self.engine_manager.add_mega_download(url, destination=dest)
            self._refresh_tasks_from_db()

    def _fetch_magnet_metadata_nonblocking(self, magnet_uri: str):
        dlg = QDialog(self)
        dlg.setWindowTitle("Fetching Magnet Metadata...")
        dlg.setModal(True)
        dlg.setFixedWidth(460)
        dlg.setStyleSheet("""
            QDialog { background-color: #121520; }
            QLabel { color: #f3f4f6; font-size: 13px; }
            QPushButton { background-color: #1a1f2e; border: 1px solid #2b334a; border-radius: 6px; padding: 8px 16px; color: #fff; }
            QPushButton:hover { background-color: #242c40; }
        """)

        layout = QVBoxLayout(dlg)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        lbl_title = QLabel("Fetching Magnet Metadata...")
        lbl_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #00d2ff;")
        layout.addWidget(lbl_title)

        lbl_status = QLabel("Bootstrapping DHT & querying trackers (0 payload bytes downloaded)...")
        lbl_status.setWordWrap(True)
        lbl_status.setStyleSheet("color: #9ca3af; font-size: 12px;")
        layout.addWidget(lbl_status)

        pbar = QProgressBar()
        pbar.setRange(0, 0)
        layout.addWidget(pbar)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

        state = {"ti": None, "error": None, "cancelled": False}
        worker = MagnetMetadataWorker(self.engine_manager, magnet_uri, timeout_seconds=60)

        def on_ready(ti):
            state["ti"] = ti
            dlg.accept()

        def on_error(err_msg):
            state["error"] = err_msg
            dlg.reject()

        def on_cancel():
            state["cancelled"] = True
            btn_cancel.setEnabled(False)
            lbl_status.setText("Cancelling magnet lookup...")
            worker.cancel()
            dlg.reject()

        worker.status_update.connect(lbl_status.setText)
        worker.metadata_ready.connect(on_ready)
        worker.error.connect(on_error)
        btn_cancel.clicked.connect(on_cancel)
        dlg.rejected.connect(lambda: worker.cancel() if state["ti"] is None and state["error"] is None else None)

        worker.start()
        dlg.exec()

        if worker.isRunning():
            worker.cancel()
            worker.wait(3000)

        if state["cancelled"] or (state["ti"] is None and state["error"] is None):
            return None
        if state["error"]:
            raise RuntimeError(state["error"])
        return state["ti"]

    def _handle_torrent_add(self, data):
        url = data["url"]
        try:
            magnet_uri = url if url.lower().startswith("magnet:") else None
            if magnet_uri:
                ti = self._fetch_magnet_metadata_nonblocking(url)
                if ti is None:
                    return
            elif url.lower().startswith(("http://", "https://")):
                import asyncio
                import aiohttp
                from ..core.ssl_context import get_ssl_context
                async def _fetch_remote_torrent():
                    connector = aiohttp.TCPConnector(ssl=get_ssl_context())
                    timeout = aiohttp.ClientTimeout(total=20, connect=10)
                    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                        async with session.get(url, allow_redirects=True) as resp:
                            if resp.status >= 400:
                                raise RuntimeError(f"HTTP {resp.status} {resp.reason}")
                            return await resp.read()
                raw_bytes = asyncio.run(_fetch_remote_torrent())
                tmp_torrent = self.engine_manager.torrent_session.metadata_dir / "remote_fetched.torrent"
                with open(tmp_torrent, "wb") as f:
                    f.write(raw_bytes)
                ti = self.engine_manager.load_torrent_file(str(tmp_torrent))
            else:
                ti = self.engine_manager.load_torrent_file(url)

            files = TorrentFileInspector.extract_files_from_torrent_info(ti)
            tdlg = TorrentDialog(
                ti.name(),
                files,
                data["destination"],
                self,
                default_stop_ratio=float(self.engine_manager.config.seeding_ratio_cutoff or 0.0),
            )
            if tdlg.exec():
                t_res = tdlg.result_data
                self.engine_manager.add_torrent_download(
                    source=ti,
                    name=ti.name(),
                    destination=t_res["destination"],
                    file_priorities=t_res["file_priorities"],
                    sequential=t_res["sequential"],
                    stop_ratio=t_res["stop_ratio"],
                    magnet_uri=magnet_uri,
                )
                self._refresh_tasks_from_db()
        except Exception as e:
            logger.exception(f"Torrent load error for {url}: {e}")
            QMessageBox.critical(self, "Torrent Error", f"Failed to load torrent metadata:\n{str(e)}")

    def _get_selected_tasks(self):
        sel_model = self.table.selectionModel()
        if not sel_model:
            return []
        rows = sorted({idx.row() for idx in sel_model.selectedRows()})
        return [self.table_model.tasks[r] for r in rows if 0 <= r < len(self.table_model.tasks)]

    def _get_selected_task(self):
        tasks = self._get_selected_tasks()
        return tasks[0] if tasks else None

    def _pause_selected(self):
        tasks = self._get_selected_tasks()
        for task in tasks:
            self.engine_manager.pause_download(task["id"])
        if tasks:
            self._refresh_tasks_from_db()

    def _resume_selected(self):
        tasks = self._get_selected_tasks()
        for task in tasks:
            self.engine_manager.resume_download(task["id"])
        if tasks:
            self._refresh_tasks_from_db()

    def _toggle_pause_resume_selected(self):
        tasks = self._get_selected_tasks()
        for task in tasks:
            if task.get("status") in ("DOWNLOADING", "QUEUED"):
                self.engine_manager.pause_download(task["id"])
            elif task.get("status") in ("PAUSED", "FAILED", "LINK EXPIRED"):
                self.engine_manager.resume_download(task["id"])
        if tasks:
            self._refresh_tasks_from_db()

    def delete_selected_tasks(self, require_confirmation: bool = True, delete_files: bool = False):
        tasks = self._get_selected_tasks()
        if not tasks:
            return 0
        if require_confirmation:
            dlg = SmartDeleteDialog(tasks, self)
            if dlg.exec() != QDialog.Accepted:
                return 0
            delete_files = dlg.chk_delete_files.isChecked()
        for task in tasks:
            self.engine_manager.delete_task(task["id"], delete_files=delete_files)
        self._refresh_tasks_from_db()
        return len(tasks)

    def _delete_selected(self):
        self.delete_selected_tasks(require_confirmation=True)

    def _open_path(self, path_str: str):
        if path_str and os.path.exists(path_str):
            if os.name == 'nt':
                os.startfile(path_str)
            else:
                subprocess.run(["xdg-open", path_str])

    def _get_completed_single_file_path(self, task: dict) -> Path | None:
        if not task or task.get("status") != "COMPLETED":
            return None
        dest = task.get("destination") or ""
        fn = task.get("filename") or ""
        if not dest or not fn:
            return None
        cand = Path(dest) / fn
        if cand.is_file():
            return cand
        return None

    def _open_selected_file(self):
        task = self._get_selected_task()
        file_path = self._get_completed_single_file_path(task)
        if file_path is not None:
            self._open_path(str(file_path))
        else:
            self._open_selected_folder()

    def _open_selected_folder(self):
        task = self._get_selected_task()
        if not task:
            return
        self._open_path(task.get("destination"))

    def _on_table_double_clicked(self, index):
        task = self._get_selected_task()
        if not task and index.isValid() and 0 <= index.row() < len(self.table_model.tasks):
            task = self.table_model.tasks[index.row()]
        file_path = self._get_completed_single_file_path(task)
        if file_path is not None:
            self._open_path(str(file_path))
        elif task:
            self._open_path(task.get("destination"))

    def _show_context_menu(self, pos):
        tasks = self._get_selected_tasks()
        if not tasks:
            return

        count = len(tasks)
        menu = QMenu(self)
        resume_label = f"Resume ({count} Selected)" if count > 1 else "Resume"
        pause_label = f"Pause ({count} Selected)" if count > 1 else "Pause"
        delete_label = f"Delete {count} Selected Tasks" if count > 1 else "Delete Task"

        act_resume = menu.addAction(get_icon("resume"), resume_label)
        act_pause = menu.addAction(get_icon("pause"), pause_label)

        act_force = None
        act_top = None
        act_open_file = None
        act_open = None
        act_err = None
        act_refresh = None
        act_inspect = None

        if count == 1:
            t0 = tasks[0]
            st0 = t0.get("status")
            if st0 in ("QUEUED", "PAUSED", "FAILED"):
                act_force = menu.addAction(get_icon("bolt"), "Force Start")
            if st0 == "QUEUED":
                act_top = menu.addAction(get_icon("resume"), "Move to Top of Queue")
            menu.addSeparator()
            if t0.get("engine_type") == "HTTP" and st0 in ("LINK EXPIRED", "FAILED", "PAUSED"):
                act_refresh = menu.addAction(get_icon("proxies"), "Refresh Download Address")
            act_inspect = menu.addAction(get_icon("activity"), "Inspect Task Details")
            if self._get_completed_single_file_path(t0) is not None:
                act_open_file = menu.addAction(get_icon("file"), "Open File")
            act_open = menu.addAction(get_icon("folder"), "Open Destination Folder")
            if t0.get("error_message"):
                act_err = menu.addAction(get_icon("warning"), "View Error Details")
            menu.addSeparator()
        else:
            menu.addSeparator()

        act_delete = menu.addAction(get_icon("delete"), delete_label)

        action = menu.exec(QCursor.pos())
        if action == act_resume:
            self._resume_selected()
        elif action == act_pause:
            self._pause_selected()
        elif act_force and action == act_force:
            self.engine_manager.force_start_task(tasks[0]["id"])
            self._refresh_tasks_from_db()
        elif act_top and action == act_top:
            self.engine_manager.move_to_top(tasks[0]["id"])
            self._refresh_tasks_from_db()
        elif act_refresh and action == act_refresh:
            dlg = RefreshAddressDialog(tasks[0], self.engine_manager, self.browser_bridge, self)
            dlg.exec()
            self._refresh_tasks_from_db()
        elif act_inspect and action == act_inspect:
            self._set_inspector_visible(True)
        elif act_open_file and action == act_open_file:
            self._open_selected_file()
        elif act_open and action == act_open:
            self._open_selected_folder()
        elif act_err and action == act_err:
            task = tasks[0]
            QMessageBox.critical(
                self,
                f"Error Details — Task #{task.get('id')}",
                f"File: {task.get('filename')}\n"
                f"URL: {task.get('url')}\n\n"
                f"Error Details:\n{task.get('error_message')}"
            )
        elif action == act_delete:
            self._delete_selected()

    @Slot(dict)
    def _on_task_progress(self, progress_dict):
        tid = progress_dict.get("task_id")
        updated = self.table_model.update_task_progress(
            tid,
            progress_dict["downloaded"],
            progress_dict["total"],
            progress_dict["speed"],
            progress_dict["eta"]
        )
        if not updated:
            self._refresh_tasks_from_db()

    @Slot(str, str)
    def _on_task_status_changed(self, task_id, status):
        updated = self.table_model.update_task_status(task_id, status)
        if not updated:
            self._refresh_tasks_from_db()

    @Slot(str, dict)
    def _on_task_completed(self, task_id, result):
        if self.engine_manager.config.notifications_enabled:
            res = result if isinstance(result, dict) else {}
            fn = res.get("filename") or f"Task #{task_id}"
            sec_status = res.get("severity") or res.get("security_status") or res.get("overall_security")
            status = res.get("status")
            action = res.get("action")

            if status == "QUARANTINED" or action == "QUARANTINED" or sec_status == "CRITICAL":
                self.tray.notify(
                    "OmniFetch Threat Quarantined",
                    f"Malicious payload isolated into vault: {fn}",
                    level="CRITICAL"
                )
            elif action == "SCAN_ERROR" or sec_status == "SCAN_ERROR":
                self.tray.notify(
                    "OmniFetch Scan Error",
                    f"Security scan failed (held in staging): {fn}",
                    level="CRITICAL"
                )
            elif sec_status in ("LOW", "WARNING") or action == "MOVED_WARNING":
                self.tray.notify(
                    "OmniFetch Security Warning",
                    f"Unsigned or suspicious PE header: {fn}",
                    level="WARNING"
                )
            else:
                self.tray.notify(
                    "OmniFetch Download Complete",
                    f"Successfully saved: {fn}",
                    level="INFO"
                )
        self._refresh_tasks_from_db()
        self._maybe_trigger_post_download_action()

    def _maybe_trigger_post_download_action(self):
        act = getattr(self.engine_manager.config, "post_download_action", "None") or "None"
        if act == "None":
            return
        if not self.engine_manager.all_tasks_terminal():
            return
        if act == "Notify Only":
            self.tray.notify(
                "OmniFetch Queue Finished",
                "All scheduled/active downloads have completed.",
                level="INFO"
            )
            return
        if act in ("Sleep PC", "Shutdown PC"):
            if "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST"):
                logger.info(f"Suppressed host power command ({act}) under pytest runtime.")
                return
            dlg = PostDownloadCountdownDialog(act, countdown_seconds=30, parent=self)
            if dlg.exec() == QDialog.Accepted:
                if act == "Sleep PC":
                    subprocess.run(["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"], check=False)
                elif act == "Shutdown PC":
                    subprocess.run(["shutdown", "/s", "/t", "5"], check=False)

    @Slot(str, str)
    def _on_task_failed(self, task_id, error_msg):
        if self.engine_manager.config.notifications_enabled:
            self.tray.notify(
                "OmniFetch Download Error",
                f"Task #{task_id} failed: {error_msg}",
                level="CRITICAL"
            )
        self._refresh_tasks_from_db()

    def handle_external_link(self, link_str: str):
        if not link_str or not link_str.strip():
            return
        link_str = link_str.strip().strip('"').strip("'")
        self.showNormal()
        self.activateWindow()
        self.raise_()

        if link_str.startswith("magnet:") or link_str.lower().endswith(".torrent"):
            self._handle_torrent_add({"url": link_str, "destination": self.engine_manager.config.download_dir})
        elif MegaUrlResolver.is_mega_url(link_str):
            self._handle_mega_add({"url": link_str, "destination": self.engine_manager.config.download_dir})
        else:
            task_id = self.engine_manager.add_download(
                url=link_str,
                destination=self.engine_manager.config.download_dir
            )
            self.engine_manager.start_download(task_id)
            self._refresh_tasks_from_db()

    def force_quit(self):
        self._is_force_quitting = True
        self.close()

    def closeEvent(self, event):
        if self._is_force_quitting or not self.engine_manager.config.minimize_to_tray:
            self.refresh_timer.stop()
            if hasattr(self, "schedule_timer"):
                self.schedule_timer.stop()
            self.browser_bridge.stop()
            self.engine_manager.shutdown()
            self.tray.hide()
            event.accept()
        else:
            event.ignore()
            self.hide()
            self.tray.notify(
                "OmniFetch Running in Background",
                "OmniFetch is minimized to the system tray. Active tasks continue."
            )
