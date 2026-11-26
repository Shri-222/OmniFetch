"""
OmniFetch Configuration Manager
Persistent user settings stored in JSON or SQLite.
Handles development vs PyInstaller frozen resource paths.
"""

import os
import sys
import json
import secrets
from pathlib import Path

DEFAULT_DOWNLOAD_DIR = str(Path.home() / "Downloads" / "OmniFetch")
DEFAULT_STAGING_DIR = str(Path.home() / "Downloads" / "OmniFetch" / ".staging")
CYBERSHIELD_ROOT = r"C:\Users\shrey\Desktop\CyberShield"

def get_resource_path(relative_path: str) -> Path:
    """
    Resolves resource paths cleanly in both dev mode and PyInstaller frozen bundle:
    - In frozen mode: sys._MEIPASS
    - In dev mode: project root C:\\Users\\shrey\\Desktop\\OmniFetch
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base_path = Path(sys._MEIPASS)
    else:
        # __file__ is app/core/config.py -> parent.parent.parent is OmniFetch root
        base_path = Path(__file__).resolve().parent.parent.parent
    return base_path / relative_path

class Config:
    def __init__(self, config_path=None):
        if config_path is None:
            self.base_dir = Path.home() / ".omnifetch"
            self.base_dir.mkdir(parents=True, exist_ok=True)
            self.config_path = self.base_dir / "config.json"
        else:
            self.config_path = Path(config_path)

        self.download_dir = DEFAULT_DOWNLOAD_DIR
        self.staging_dir = DEFAULT_STAGING_DIR
        self.max_concurrent_tasks = 4
        self.max_segments_per_task = 8  # 1 to 16
        self.cybershield_enabled = True
        self.cybershield_root = CYBERSHIELD_ROOT
        self.speed_limit_kbs = 0  # 0 = unlimited
        self.minimize_to_tray = True
        self.notifications_enabled = True
        self.seeding_ratio_cutoff = 0.0  # 0.0 = stop seeding immediately
        self.brave_handoff_port = 8990
        self.brave_handoff_token = secrets.token_hex(16)
        self.column_widths = {}
        self.proxies = []
        self.proxy_passive_mode = True
        self.bt_listen_port = 6881
        self.bt_enable_dht = True
        self.bt_enable_pex_lsd = True
        self.bt_enable_upnp = True
        self.bt_encryption_mode = "prefer"  # "prefer", "require", "disabled"
        self.bt_max_connections = 200
        self.bt_max_peers_per_torrent = 60
        self.auto_extract_archives = False
        self.schedule_enabled = False
        self.schedule_start_time = "00:00"
        self.schedule_stop_time = "06:00"
        self.post_download_action = "None"  # "None", "Notify Only", "Sleep PC", "Shutdown PC"
        self.auto_categorize_folders = False
        self.load()

    @property
    def speed_limit_bytes_per_sec(self) -> int:
        return self.speed_limit_kbs * 1024

    @speed_limit_bytes_per_sec.setter
    def speed_limit_bytes_per_sec(self, val: int):
        self.speed_limit_kbs = int(val) // 1024

    def load(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.download_dir = data.get("download_dir", self.download_dir)
                    self.staging_dir = data.get("staging_dir", self.staging_dir)
                    self.max_concurrent_tasks = data.get("max_concurrent_tasks", self.max_concurrent_tasks)
                    self.max_segments_per_task = data.get("max_segments_per_task", self.max_segments_per_task)
                    self.cybershield_enabled = data.get("cybershield_enabled", self.cybershield_enabled)
                    self.cybershield_root = data.get("cybershield_root", self.cybershield_root)
                    self.speed_limit_kbs = data.get("speed_limit_kbs", data.get("speed_limit_bytes_per_sec", 0) // 1024 if "speed_limit_bytes_per_sec" in data else self.speed_limit_kbs)
                    self.minimize_to_tray = data.get("minimize_to_tray", self.minimize_to_tray)
                    self.notifications_enabled = data.get("notifications_enabled", self.notifications_enabled)
                    self.seeding_ratio_cutoff = data.get("seeding_ratio_cutoff", self.seeding_ratio_cutoff)
                    self.brave_handoff_port = data.get("brave_handoff_port", self.brave_handoff_port)
                    self.brave_handoff_token = data.get("brave_handoff_token", self.brave_handoff_token)
                    self.column_widths = data.get("column_widths", self.column_widths)
                    self.proxies = list(data.get("proxies", self.proxies) or [])
                    self.proxy_passive_mode = bool(data.get("proxy_passive_mode", self.proxy_passive_mode))
                    self.bt_listen_port = int(data.get("bt_listen_port", self.bt_listen_port))
                    self.bt_enable_dht = bool(data.get("bt_enable_dht", self.bt_enable_dht))
                    self.bt_enable_pex_lsd = bool(data.get("bt_enable_pex_lsd", self.bt_enable_pex_lsd))
                    self.bt_enable_upnp = bool(data.get("bt_enable_upnp", self.bt_enable_upnp))
                    self.bt_encryption_mode = str(data.get("bt_encryption_mode", self.bt_encryption_mode) or "prefer")
                    self.bt_max_connections = int(data.get("bt_max_connections", self.bt_max_connections))
                    self.bt_max_peers_per_torrent = int(data.get("bt_max_peers_per_torrent", self.bt_max_peers_per_torrent))
                    self.auto_extract_archives = bool(data.get("auto_extract_archives", self.auto_extract_archives))
                    self.schedule_enabled = bool(data.get("schedule_enabled", self.schedule_enabled))
                    self.schedule_start_time = str(data.get("schedule_start_time", self.schedule_start_time) or "00:00")
                    self.schedule_stop_time = str(data.get("schedule_stop_time", self.schedule_stop_time) or "06:00")
                    self.post_download_action = str(data.get("post_download_action", self.post_download_action) or "None")
                    self.auto_categorize_folders = bool(data.get("auto_categorize_folders", self.auto_categorize_folders))
            except Exception:
                pass

    def save(self):
        data = {
            "download_dir": self.download_dir,
            "staging_dir": self.staging_dir,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "max_segments_per_task": self.max_segments_per_task,
            "cybershield_enabled": self.cybershield_enabled,
            "cybershield_root": self.cybershield_root,
            "speed_limit_kbs": self.speed_limit_kbs,
            "minimize_to_tray": self.minimize_to_tray,
            "notifications_enabled": self.notifications_enabled,
            "seeding_ratio_cutoff": self.seeding_ratio_cutoff,
            "brave_handoff_port": self.brave_handoff_port,
            "brave_handoff_token": self.brave_handoff_token,
            "column_widths": self.column_widths,
            "proxies": list(self.proxies or []),
            "proxy_passive_mode": bool(self.proxy_passive_mode),
            "bt_listen_port": int(self.bt_listen_port),
            "bt_enable_dht": bool(self.bt_enable_dht),
            "bt_enable_pex_lsd": bool(self.bt_enable_pex_lsd),
            "bt_enable_upnp": bool(self.bt_enable_upnp),
            "bt_encryption_mode": self.bt_encryption_mode,
            "bt_max_connections": int(self.bt_max_connections),
            "bt_max_peers_per_torrent": int(self.bt_max_peers_per_torrent),
            "auto_extract_archives": bool(self.auto_extract_archives),
            "schedule_enabled": bool(self.schedule_enabled),
            "schedule_start_time": self.schedule_start_time,
            "schedule_stop_time": self.schedule_stop_time,
            "post_download_action": self.post_download_action,
            "auto_categorize_folders": bool(self.auto_categorize_folders),
        }
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
