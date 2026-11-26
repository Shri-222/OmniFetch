"""
Phase 4 Integration Tests for OmniFetch
Tests:
1. Global Speed Limiter (HTTP token bucket and Torrent session rate limits)
2. Browser Handoff Bridge (authenticated GET /api/ping, 401 on bad token, POST /api/handoff with headers)
3. Single-Instance IPC communication via QLocalServer / QLocalSocket
4. Resource path resolution in dev vs frozen (PyInstaller sys._MEIPASS) modes
5. Settings and database persistence for custom headers
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
import pytest
from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from app.core.config import Config, get_resource_path
from app.core.db import Database
from app.core.engine_manager import EngineManager
from app.integrations.browser_bridge import BrowserHandoffBridge

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app

def test_resource_path_resolution(monkeypatch):
    """Verify get_resource_path resolves properly in both standard dev and PyInstaller frozen modes."""
    # 1. Dev mode (sys._MEIPASS not present)
    dev_path = get_resource_path("app/assets/omnifetch.ico")
    assert dev_path.name == "omnifetch.ico"

    # 2. Frozen mode simulation
    fake_meipass = Path("C:/fake_meipass_omnifetch")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(fake_meipass), raising=False)
    frozen_path = get_resource_path("app/assets/omnifetch.ico")
    assert str(frozen_path).startswith(str(fake_meipass))

def test_global_speed_limiter_configuration(tmp_path):
    """Verify Config and EngineManager properly apply global speed limits."""
    cfg_file = tmp_path / "config.json"
    cfg = Config(config_path=cfg_file)
    assert cfg.speed_limit_kbs == 0

    cfg.speed_limit_kbs = 2048
    cfg.save()
    assert cfg.speed_limit_kbs == 2048

    # Verify persistence
    cfg2 = Config(config_path=cfg_file)
    assert cfg2.speed_limit_kbs == 2048

    # Test EngineManager applying speed limit
    db = Database(db_path=tmp_path / "test.db")
    mgr = EngineManager(cfg2, db)

    mgr.set_global_speed_limit(1024)
    assert mgr.rate_limiter.rate_limit_bytes_per_sec == 1024 * 1024

    mgr.set_global_speed_limit(0)
    assert mgr.rate_limiter.rate_limit_bytes_per_sec == 0
    mgr.shutdown()

def test_browser_handoff_bridge_auth_and_routing(tmp_path, qapp):
    """Verify BrowserHandoffBridge authentication, ping, and download handoff."""
    test_port = 19888
    secret_token = "test_token_secret_12345"

    cfg = Config(config_path=tmp_path / "cfg.json")
    cfg.brave_handoff_port = test_port
    cfg.brave_handoff_token = secret_token
    db = Database(db_path=tmp_path / "tasks.db")
    mgr = EngineManager(cfg, db)

    bridge = BrowserHandoffBridge(cfg, mgr)
    assert bridge.start()
    time.sleep(0.3)

    base_url = f"http://127.0.0.1:{test_port}"

    # 1. Test ping without token -> 401 Unauthorized
    req_no_auth = urllib.request.Request(f"{base_url}/api/ping")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_no_auth)
    assert exc_info.value.code == 401

    # 2. Test ping with invalid token -> 401 Unauthorized
    req_bad_auth = urllib.request.Request(f"{base_url}/api/ping", headers={"X-OmniFetch-Token": "wrong"})
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_bad_auth)
    assert exc_info.value.code == 401

    # 3. Test ping with valid token -> 200 OK
    req_valid = urllib.request.Request(f"{base_url}/api/ping", headers={"X-OmniFetch-Token": secret_token})
    with urllib.request.urlopen(req_valid) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data.get("status") == "ok"
        assert data.get("app") == "OmniFetch"

    # 4. Test POST /api/handoff with headers (Cookie, Referer, User-Agent)
    handoff_payload = json.dumps({
        "url": "https://example.com/test_handoff_file.iso",
        "filename": "test_handoff_file.iso",
        "cookies": "sessionId=xyz987; user=test",
        "referer": "https://example.com/download_page",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Brave/120.0"
    }).encode("utf-8")

    req_handoff = urllib.request.Request(
        f"{base_url}/api/handoff",
        data=handoff_payload,
        headers={
            "X-OmniFetch-Token": secret_token,
            "Content-Type": "application/json"
        },
        method="POST"
    )

    received_signals = []
    bridge.download_received.connect(lambda url, tid: received_signals.append((url, tid)))

    with urllib.request.urlopen(req_handoff) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res.get("status") == "ok"
        task_id = res.get("task_id")
        assert task_id is not None

    for _ in range(20):
        qapp.processEvents()
        if received_signals:
            break
        time.sleep(0.05)

    assert len(received_signals) == 1
    assert received_signals[0][0] == "https://example.com/test_handoff_file.iso"

    # Verify task was added to DB with custom_headers
    task = db.get_task(task_id)
    assert task is not None
    assert task["url"] == "https://example.com/test_handoff_file.iso"
    assert task["filename"] == "test_handoff_file.iso"
    headers = task.get("custom_headers") or {}
    assert headers.get("Cookie") == "sessionId=xyz987; user=test"
    assert headers.get("Referer") == "https://example.com/download_page"
    assert headers.get("User-Agent") == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Brave/120.0"

    bridge.stop()
    mgr.shutdown()

def test_single_instance_ipc_socket(qapp):
    """Verify single-instance QLocalServer / QLocalSocket link exchange."""
    pipe_name = "OmniFetch_Test_IPC_Socket"
    QLocalServer.removeServer(pipe_name)

    server = QLocalServer()
    assert server.listen(pipe_name)

    received_messages = []

    def on_connection():
        sock = server.nextPendingConnection()
        if sock:
            def on_read():
                msg = bytes(sock.readAll()).decode("utf-8")
                received_messages.append(msg)
            sock.readyRead.connect(on_read)

    server.newConnection.connect(on_connection)

    # Secondary instance client socket
    client = QLocalSocket()
    client.connectToServer(pipe_name)
    assert client.waitForConnected(1000)

    test_args = ["https://example.com/file1.zip", "magnet:?xt=urn:btih:abcdef"]
    payload = json.dumps(test_args).encode("utf-8")
    client.write(payload)
    client.waitForBytesWritten(1000)

    # Process events to deliver IPC message
    for _ in range(10):
        qapp.processEvents()
        if received_messages:
            break
        time.sleep(0.05)

    client.disconnectFromServer()
    server.close()

    assert len(received_messages) == 1
    parsed = json.loads(received_messages[0])
    assert parsed == test_args
