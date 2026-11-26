"""
OmniFetch System Tray Integration & Native Windows Notifications
Provides background tray operation, minimize-to-tray handling, quick task controls,
and native toast notifications for complete, crack warnings, and quarantine events.
"""

from pathlib import Path
from PySide6.QtWidgets import QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QObject

from ..core.config import get_resource_path
from .icons import get_icon

class OmniFetchTray(QSystemTrayIcon):
    def __init__(self, main_window, engine_manager, clipboard_listener=None, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        self.engine_manager = engine_manager
        self.clipboard_listener = clipboard_listener

        # Load icon
        ico_file = get_resource_path("app/assets/omnifetch.ico")
        if ico_file.exists():
            self.setIcon(QIcon(str(ico_file)))
        else:
            self.setIcon(get_icon("app", size=32))

        self.setToolTip("OmniFetch — Download Manager & CyberShield Gate")
        self._init_menu()
        self.activated.connect(self._on_tray_activated)

    def _init_menu(self):
        self.menu = QMenu()

        act_show = QAction("Open OmniFetch", self)
        act_show.triggered.connect(self._show_window)
        self.menu.addAction(act_show)

        self.menu.addSeparator()

        act_pause = QAction("Pause All", self)
        act_pause.setIcon(get_icon("pause", size=16))
        act_pause.triggered.connect(self.engine_manager.pause_all)
        self.menu.addAction(act_pause)

        act_resume = QAction("Resume All", self)
        act_resume.setIcon(get_icon("resume", size=16))
        act_resume.triggered.connect(self.engine_manager.resume_all)
        self.menu.addAction(act_resume)

        self.menu.addSeparator()

        if self.clipboard_listener:
            self.act_grabber = QAction("Clipboard Grabber: ON", self)
            self.act_grabber.setIcon(get_icon("clipboard", size=16))
            self.act_grabber.triggered.connect(self._toggle_grabber)
            self.menu.addAction(self.act_grabber)

        self.menu.addSeparator()

        act_quit = QAction("Quit OmniFetch", self)
        act_quit.triggered.connect(self._quit_app)
        self.menu.addAction(act_quit)

        self.setContextMenu(self.menu)

    def _show_window(self):
        self.main_window.show()
        self.main_window.showNormal()
        self.main_window.raise_()
        self.main_window.activateWindow()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.main_window.isVisible():
                if self.main_window.isMinimized():
                    self._show_window()
                else:
                    self.main_window.hide()
            else:
                self._show_window()

    def _toggle_grabber(self):
        if self.clipboard_listener:
            is_on = self.clipboard_listener.toggle()
            self.act_grabber.setText(f"Clipboard Grabber: {'ON' if is_on else 'OFF'}")

    def _quit_app(self):
        self.main_window.force_quit()

    def notify(self, title: str, message: str, level: str = "INFO"):
        """Dispatches native Windows notifications."""
        if not self.engine_manager.config.notifications_enabled:
            return

        if level == "CRITICAL":
            icon = QSystemTrayIcon.Critical
        elif level == "WARNING":
            icon = QSystemTrayIcon.Warning
        else:
            icon = QSystemTrayIcon.Information

        self.showMessage(title, message, icon, 5000)
