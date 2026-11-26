"""
OmniFetch — Native Desktop Download Manager Entry Point
Includes Windows AppUserModelID registration, Single-Instance Guard (QLocalServer/QLocalSocket),
and CLI argument forwarding for .torrent files, magnets, and web links.
"""

import sys
import os
import json
import ctypes
from pathlib import Path

# Ensure app package root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from app.core.config import Config
from app.core.db import Database
from app.core.engine_manager import EngineManager
from app.core.logger import init_logging, get_logger
from app.core.ssl_context import setup_ssl_environment
from app.ui.main_window import MainWindow

IPC_SERVER_NAME = "OmniFetch_SingleInstance_IPC"
logger = get_logger("main")

def register_windows_app_id():
    """Register explicit AppUserModelID on Windows for native taskbar and toast grouping."""
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("OmniFetch.DownloadManager")
        except Exception:
            pass

def send_args_to_running_instance(args: list) -> bool:
    """Attempt to connect to an existing running OmniFetch instance and forward args."""
    socket = QLocalSocket()
    socket.connectToServer(IPC_SERVER_NAME)
    if socket.waitForConnected(600):
        payload = json.dumps(args).encode("utf-8")
        socket.write(payload)
        socket.waitForBytesWritten(1000)
        socket.disconnectFromServer()
        return True
    return False

def main():
    init_logging()
    setup_ssl_environment()
    register_windows_app_id()
    logger.info("Starting OmniFetch application...")

    # Enable High DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("OmniFetch")
    app.setOrganizationName("OmniFetch")

    cli_args = [arg for arg in sys.argv[1:] if arg and not arg.startswith("--")]

    # Check if an instance is already running
    if send_args_to_running_instance(cli_args):
        # Forwarded successfully to the existing instance — exit secondary process
        sys.exit(0)

    # First instance: Setup Single-Instance IPC Server
    QLocalServer.removeServer(IPC_SERVER_NAME)
    ipc_server = QLocalServer()
    ipc_server.listen(IPC_SERVER_NAME)

    config = Config()
    db = Database()
    engine_manager = EngineManager(config, db)

    window = MainWindow(engine_manager)
    window.show()

    # Handle incoming IPC connections from secondary instances or CLI calls
    def on_new_connection():
        client_sock = ipc_server.nextPendingConnection()
        if not client_sock:
            return

        def on_ready_read():
            raw_data = bytes(client_sock.readAll()).decode("utf-8", errors="ignore")
            if raw_data:
                try:
                    args = json.loads(raw_data)
                    if isinstance(args, list):
                        for a in args:
                            window.handle_external_link(a)
                    else:
                        window.handle_external_link(str(args))
                except Exception:
                    window.handle_external_link(raw_data)
            window.showNormal()
            window.activateWindow()
            window.raise_()

        client_sock.readyRead.connect(on_ready_read)

    ipc_server.newConnection.connect(on_new_connection)

    # Process any initial CLI arguments passed to this first instance
    for arg in cli_args:
        window.handle_external_link(arg)

    ret = app.exec()
    ipc_server.close()
    sys.exit(ret)

if __name__ == "__main__":
    main()
