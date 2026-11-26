"""
OmniFetch Settings Dialog
Tabbed configuration UI covering General/Storage/Orphan GC, Global Bandwidth,
BitTorrent Network & Encryption, Daily Queue Schedule & Post-Download Automation,
and Safe 1-Click Brave Extension Pairing.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QDoubleSpinBox, QCheckBox,
    QFileDialog, QGroupBox, QMessageBox, QTabWidget, QWidget,
    QComboBox, QTimeEdit
)
from PySide6.QtCore import Qt, QTimer, QTime

from ..core.config import Config
from ..core.db import Database
from ..core.staging import StagingManager
from .icons import get_icon


class SettingsDialog(QDialog):
    def __init__(self, config: Config, parent=None, engine_manager=None, browser_bridge=None):
        super().__init__(parent)
        self.config = config
        self.engine_manager = engine_manager
        self.browser_bridge = browser_bridge
        self._pair_seconds_left = 0
        self._pair_timer = QTimer(self)
        self._pair_timer.setInterval(1000)
        self._pair_timer.timeout.connect(self._on_pair_timer_tick)
        if self.browser_bridge and hasattr(self.browser_bridge, "pairing_completed"):
            self.browser_bridge.pairing_completed.connect(self._on_pairing_completed, Qt.QueuedConnection)

        self.setWindowTitle("OmniFetch Settings")
        self.resize(600, 580)
        self.setWindowIcon(get_icon("settings", size=24))
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # ---- TAB 1: General & Storage ----
        tab_general = QWidget()
        gen_layout = QVBoxLayout(tab_general)
        gen_layout.setSpacing(12)

        storage_grp = QGroupBox("Storage & Staging Maintenance")
        storage_layout = QGridLayout(storage_grp)

        storage_layout.addWidget(QLabel("Default Download Folder:"), 0, 0)
        self.dest_edit = QLineEdit(self.config.download_dir)
        storage_layout.addWidget(self.dest_edit, 0, 1)

        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse_dest)
        storage_layout.addWidget(btn_browse, 0, 2)

        self.btn_clean_staging = QPushButton("Clean Orphan Staging Cache")
        self.btn_clean_staging.setIcon(get_icon("delete"))
        self.btn_clean_staging.clicked.connect(self._clean_orphan_staging)
        storage_layout.addWidget(self.btn_clean_staging, 1, 0, 1, 3)

        gen_layout.addWidget(storage_grp)

        perf_grp = QGroupBox("Engine & Bandwidth")
        perf_layout = QGridLayout(perf_grp)

        perf_layout.addWidget(QLabel("Max HTTP Connections (1–16):"), 0, 0)
        self.spin_segments = QSpinBox()
        self.spin_segments.setRange(1, 16)
        self.spin_segments.setValue(self.config.max_segments_per_task)
        perf_layout.addWidget(self.spin_segments, 0, 1)

        perf_layout.addWidget(QLabel("Max Concurrent Downloads:"), 1, 0)
        self.spin_concurrent = QSpinBox()
        self.spin_concurrent.setRange(1, 10)
        self.spin_concurrent.setValue(self.config.max_concurrent_tasks)
        perf_layout.addWidget(self.spin_concurrent, 1, 1)

        perf_layout.addWidget(QLabel("Global Speed Cap (KB/s, 0 = Unlimited):"), 2, 0)
        self.spin_speed_cap = QSpinBox()
        self.spin_speed_cap.setRange(0, 1000000)
        self.spin_speed_cap.setValue(self.config.speed_limit_kbs)
        self.spin_speed_cap.setSingleStep(512)
        perf_layout.addWidget(self.spin_speed_cap, 2, 1)

        gen_layout.addWidget(perf_grp)

        sys_grp = QGroupBox("System, Tray & Archive Extraction")
        sys_layout = QVBoxLayout(sys_grp)

        self.chk_auto_extract = QCheckBox(
            "Auto-extract clean archives (.zip/.tar) after CyberShield Stage 3 verification"
        )
        self.chk_auto_extract.setChecked(bool(getattr(self.config, "auto_extract_archives", False)))
        sys_layout.addWidget(self.chk_auto_extract)

        self.chk_auto_categorize = QCheckBox(
            "Auto-categorize downloads into subfolders (Videos, Archives, Programs, Documents, Images)"
        )
        self.chk_auto_categorize.setChecked(bool(getattr(self.config, "auto_categorize_folders", False)))
        sys_layout.addWidget(self.chk_auto_categorize)

        self.chk_tray = QCheckBox("Minimize to System Tray on close/minimize")
        self.chk_tray.setChecked(self.config.minimize_to_tray)
        sys_layout.addWidget(self.chk_tray)

        self.chk_notify = QCheckBox("Show Windows Native Notifications on Complete / Threat Quarantined")
        self.chk_notify.setChecked(self.config.notifications_enabled)
        sys_layout.addWidget(self.chk_notify)

        gen_layout.addWidget(sys_grp)
        gen_layout.addStretch()
        self.tabs.addTab(tab_general, "General")

        # ---- TAB 2: BitTorrent Network & Session Controls ----
        tab_bt = QWidget()
        bt_layout = QVBoxLayout(tab_bt)
        bt_layout.setSpacing(12)

        bt_net_grp = QGroupBox("BitTorrent Network & Session Settings")
        bt_grid = QGridLayout(bt_net_grp)

        bt_grid.addWidget(QLabel("Listen Port (0 = Random):"), 0, 0)
        self.spin_bt_port = QSpinBox()
        self.spin_bt_port.setRange(0, 65535)
        self.spin_bt_port.setValue(int(getattr(self.config, "bt_listen_port", 6881)))
        bt_grid.addWidget(self.spin_bt_port, 0, 1)

        bt_grid.addWidget(QLabel("Protocol Encryption:"), 1, 0)
        self.combo_bt_enc = QComboBox()
        self.combo_bt_enc.addItem("Prefer Encrypted", "prefer")
        self.combo_bt_enc.addItem("Require Encrypted", "require")
        self.combo_bt_enc.addItem("Disabled", "disabled")
        enc_idx = self.combo_bt_enc.findData(str(getattr(self.config, "bt_encryption_mode", "prefer")).lower())
        self.combo_bt_enc.setCurrentIndex(max(0, enc_idx))
        bt_grid.addWidget(self.combo_bt_enc, 1, 1)

        bt_grid.addWidget(QLabel("Max Active Global Connections:"), 2, 0)
        self.spin_bt_conns = QSpinBox()
        self.spin_bt_conns.setRange(10, 2000)
        self.spin_bt_conns.setValue(int(getattr(self.config, "bt_max_connections", 200)))
        bt_grid.addWidget(self.spin_bt_conns, 2, 1)

        bt_grid.addWidget(QLabel("Max Peers Per Torrent:"), 3, 0)
        self.spin_bt_peers = QSpinBox()
        self.spin_bt_peers.setRange(5, 500)
        self.spin_bt_peers.setValue(int(getattr(self.config, "bt_max_peers_per_torrent", 60)))
        bt_grid.addWidget(self.spin_bt_peers, 3, 1)

        bt_grid.addWidget(QLabel("Auto-Stop Seeding Ratio:"), 4, 0)
        self.spin_ratio = QDoubleSpinBox()
        self.spin_ratio.setRange(0.0, 10.0)
        self.spin_ratio.setSingleStep(0.5)
        self.spin_ratio.setValue(self.config.seeding_ratio_cutoff)
        bt_grid.addWidget(self.spin_ratio, 4, 1)

        bt_layout.addWidget(bt_net_grp)

        bt_flags_grp = QGroupBox("Peer Discovery Protocols")
        bt_flags_layout = QVBoxLayout(bt_flags_grp)
        self.chk_bt_dht = QCheckBox("Enable DHT (Distributed Hash Table)")
        self.chk_bt_dht.setChecked(bool(getattr(self.config, "bt_enable_dht", True)))
        bt_flags_layout.addWidget(self.chk_bt_dht)

        self.chk_bt_pex = QCheckBox("Enable PEX & Local Peer Discovery (LSD)")
        self.chk_bt_pex.setChecked(bool(getattr(self.config, "bt_enable_pex_lsd", True)))
        bt_flags_layout.addWidget(self.chk_bt_pex)

        self.chk_bt_upnp = QCheckBox("Enable UPnP / NAT-PMP Port Mapping")
        self.chk_bt_upnp.setChecked(bool(getattr(self.config, "bt_enable_upnp", True)))
        bt_flags_layout.addWidget(self.chk_bt_upnp)

        bt_layout.addWidget(bt_flags_grp)
        bt_layout.addStretch()
        self.tabs.addTab(tab_bt, "BitTorrent")

        # ---- TAB 3: Schedule & Post-Download Automation ----
        tab_sched = QWidget()
        sched_layout = QVBoxLayout(tab_sched)
        sched_layout.setSpacing(12)

        sched_grp = QGroupBox("Daily Download Queue Schedule")
        sched_grid = QGridLayout(sched_grp)

        self.chk_sched_enabled = QCheckBox("Enable Daily Schedule Window (Auto-resume inside / Auto-pause outside)")
        self.chk_sched_enabled.setChecked(bool(getattr(self.config, "schedule_enabled", False)))
        sched_grid.addWidget(self.chk_sched_enabled, 0, 0, 1, 2)

        sched_grid.addWidget(QLabel("Start Time (HH:MM):"), 1, 0)
        self.time_start = QTimeEdit()
        self.time_start.setDisplayFormat("HH:mm")
        self.time_start.setTime(QTime.fromString(getattr(self.config, "schedule_start_time", "00:00"), "HH:mm") or QTime(0, 0))
        sched_grid.addWidget(self.time_start, 1, 1)

        sched_grid.addWidget(QLabel("Stop Time (HH:MM):"), 2, 0)
        self.time_stop = QTimeEdit()
        self.time_stop.setDisplayFormat("HH:mm")
        self.time_stop.setTime(QTime.fromString(getattr(self.config, "schedule_stop_time", "06:00"), "HH:mm") or QTime(6, 0))
        sched_grid.addWidget(self.time_stop, 2, 1)

        sched_layout.addWidget(sched_grp)

        post_grp = QGroupBox("Safe Post-Download Power Automation")
        post_grid = QGridLayout(post_grp)
        post_grid.addWidget(QLabel("When ALL queued/active downloads finish:"), 0, 0)
        self.combo_post_action = QComboBox()
        for act in ("None", "Notify Only", "Sleep PC", "Shutdown PC"):
            self.combo_post_action.addItem(act, act)
        p_idx = self.combo_post_action.findData(getattr(self.config, "post_download_action", "None"))
        self.combo_post_action.setCurrentIndex(max(0, p_idx))
        post_grid.addWidget(self.combo_post_action, 0, 1)

        note_lbl = QLabel("Sleep / Shutdown ALWAYS display a 30-second cancellable countdown before executing.")
        note_lbl.setStyleSheet("color: #9ca3af; font-size: 11px;")
        post_grid.addWidget(note_lbl, 1, 0, 1, 2)
        sched_layout.addWidget(post_grp)
        sched_layout.addStretch()
        self.tabs.addTab(tab_sched, "Schedule && Automation")

        # ---- TAB 4: Brave Browser Bridge & 1-Click Pairing ----
        tab_brave = QWidget()
        brave_vlayout = QVBoxLayout(tab_brave)
        brave_vlayout.setSpacing(12)

        brave_grp = QGroupBox("Brave Browser Handoff Bridge")
        brave_layout = QGridLayout(brave_grp)

        brave_layout.addWidget(QLabel("Local Bridge Port:"), 0, 0)
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1024, 65535)
        self.spin_port.setValue(self.config.brave_handoff_port)
        brave_layout.addWidget(self.spin_port, 0, 1)

        brave_layout.addWidget(QLabel("Secret Token (X-OmniFetch-Token):"), 1, 0)
        token_row = QHBoxLayout()
        self.token_edit = QLineEdit(self.config.brave_handoff_token)
        self.token_edit.setReadOnly(True)
        token_row.addWidget(self.token_edit)

        btn_copy_token = QPushButton("Copy")
        btn_copy_token.clicked.connect(self._copy_token)
        token_row.addWidget(btn_copy_token)
        brave_layout.addLayout(token_row, 1, 1)

        pair_row = QHBoxLayout()
        self.btn_pair_brave = QPushButton("Pair Brave Extension (60s)")
        self.btn_pair_brave.setObjectName("btnPrimary")
        self.btn_pair_brave.clicked.connect(self._start_pairing_window)
        pair_row.addWidget(self.btn_pair_brave)

        self.lbl_pair_status = QLabel("Pairing window closed (1-click sync only open when active).")
        self.lbl_pair_status.setStyleSheet("color: #9ca3af; font-size: 11px;")
        pair_row.addWidget(self.lbl_pair_status, 1)
        brave_layout.addLayout(pair_row, 2, 0, 1, 2)

        brave_vlayout.addWidget(brave_grp)
        brave_vlayout.addStretch()
        self.tabs.addTab(tab_brave, "Brave Bridge")

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_save = QPushButton("Save & Apply")
        btn_save.setObjectName("btnAccent")
        btn_save.clicked.connect(self._save_settings)
        btn_row.addWidget(btn_save)

        layout.addLayout(btn_row)

    def _browse_dest(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Default Download Directory", self.dest_edit.text())
        if folder:
            self.dest_edit.setText(folder)

    def _clean_orphan_staging(self):
        if self.engine_manager is not None:
            res = self.engine_manager.clean_orphaned_staging(min_age_seconds=0)
        else:
            sm = StagingManager(self.config.staging_dir)
            db = Database()
            try:
                active_ids = {t["id"] for t in db.get_all_tasks()}
                res = sm.cleanup_orphaned_staging(active_ids, min_age_seconds=0)
            finally:
                db.close()
        QMessageBox.information(
            self,
            "Staging Cache Cleaned",
            f"Removed {res['removed_count']} orphan folder(s) and reclaimed {res['reclaimed_mb']} MB.",
        )

    def _copy_token(self):
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(self.token_edit.text())
            QMessageBox.information(self, "Token Copied", "Secret handoff token copied to clipboard.")

    def _start_pairing_window(self):
        if not self.browser_bridge:
            QMessageBox.warning(self, "Bridge Unavailable", "Browser Handoff Bridge is not running.")
            return
        self.browser_bridge.open_pairing_window(60)
        self._pair_seconds_left = 60
        self.lbl_pair_status.setStyleSheet("color: #00d2ff; font-weight: 600; font-size: 11px;")
        self.lbl_pair_status.setText("Pairing Open: 60s left — click 'Auto-Pair' in Brave now.")
        self._pair_timer.start()

    def _on_pair_timer_tick(self):
        self._pair_seconds_left -= 1
        if self._pair_seconds_left <= 0:
            self._pair_timer.stop()
            if self.browser_bridge:
                self.browser_bridge.close_pairing_window()
            self.lbl_pair_status.setStyleSheet("color: #9ca3af; font-size: 11px;")
            self.lbl_pair_status.setText("Pairing window closed.")
        else:
            self.lbl_pair_status.setText(
                f"Pairing Open: {self._pair_seconds_left}s left — click 'Auto-Pair' in Brave now."
            )

    def _on_pairing_completed(self):
        self._pair_timer.stop()
        self._pair_seconds_left = 0
        self.lbl_pair_status.setStyleSheet("color: #10b981; font-weight: 600; font-size: 11px;")
        self.lbl_pair_status.setText("Brave Extension paired cleanly! Window closed.")

    def _save_settings(self):
        self.config.download_dir = self.dest_edit.text().strip()
        self.config.max_segments_per_task = self.spin_segments.value()
        self.config.max_concurrent_tasks = self.spin_concurrent.value()
        self.config.speed_limit_kbs = self.spin_speed_cap.value()
        self.config.auto_extract_archives = self.chk_auto_extract.isChecked()
        self.config.auto_categorize_folders = self.chk_auto_categorize.isChecked()
        self.config.minimize_to_tray = self.chk_tray.isChecked()
        self.config.notifications_enabled = self.chk_notify.isChecked()

        # BitTorrent settings
        self.config.bt_listen_port = self.spin_bt_port.value()
        self.config.bt_encryption_mode = self.combo_bt_enc.currentData() or "prefer"
        self.config.bt_max_connections = self.spin_bt_conns.value()
        self.config.bt_max_peers_per_torrent = self.spin_bt_peers.value()
        self.config.bt_enable_dht = self.chk_bt_dht.isChecked()
        self.config.bt_enable_pex_lsd = self.chk_bt_pex.isChecked()
        self.config.bt_enable_upnp = self.chk_bt_upnp.isChecked()
        self.config.seeding_ratio_cutoff = self.spin_ratio.value()

        # Schedule & post-download automation
        self.config.schedule_enabled = self.chk_sched_enabled.isChecked()
        self.config.schedule_start_time = self.time_start.time().toString("HH:mm")
        self.config.schedule_stop_time = self.time_stop.time().toString("HH:mm")
        self.config.post_download_action = self.combo_post_action.currentData() or "None"

        self.config.brave_handoff_port = self.spin_port.value()
        self.config.save()

        if self.engine_manager is not None:
            self.engine_manager.set_global_speed_limit(self.config.speed_limit_kbs)
            self.engine_manager.apply_torrent_settings()
        self.accept()

    def closeEvent(self, event):
        self._pair_timer.stop()
        if self.browser_bridge:
            self.browser_bridge.close_pairing_window()
        super().closeEvent(event)

    def reject(self):
        self._pair_timer.stop()
        if self.browser_bridge:
            self.browser_bridge.close_pairing_window()
        super().reject()
