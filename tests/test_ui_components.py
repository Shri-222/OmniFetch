"""
Tests for UI Table Models, Formatting Delegates, and Engine Coordinator
"""

import sys
import time
import socket
import asyncio
import hashlib
import threading
import pytest
from aiohttp import web
from PySide6.QtCore import Qt, QItemSelectionModel, QItemSelection
from PySide6.QtWidgets import QApplication, QAbstractItemView, QHeaderView
from app.ui.download_table import format_bytes, format_eta, DownloadTableModel
from app.ui.add_dialog import AddDownloadDialog
from app.ui.main_window import MainWindow
from app.core.config import Config
from app.core.db import Database
from app.core.engine_manager import EngineManager

@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app

def test_format_bytes():
    assert format_bytes(0) == "0 B"
    assert format_bytes(512) == "512.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024 * 15) == "15.0 MB"
    assert format_bytes(1024 * 1024 * 1024 * 3) == "3.0 GB"

def test_format_eta():
    assert format_eta(0) == "--"
    assert format_eta(45) == "45s"
    assert format_eta(125) == "2m 5s"
    assert format_eta(3665) == "1h 1m"

def test_download_table_model():
    model = DownloadTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == 9

    sample_tasks = [
        {
            "id": "t1",
            "filename": "sample_movie.mp4",
            "downloaded_bytes": 500 * 1024 * 1024,
            "total_bytes": 1000 * 1024 * 1024,
            "speed_bps": 5 * 1024 * 1024,
            "eta_seconds": 100,
            "resumable": 1,
            "engine_type": "HTTP",
            "status": "DOWNLOADING",
            "security_status": "CLEAN"
        },
        {
            "id": "t2",
            "filename": "game_crack.zip",
            "downloaded_bytes": 1000 * 1024 * 1024,
            "total_bytes": 1000 * 1024 * 1024,
            "speed_bps": 0,
            "eta_seconds": 0,
            "resumable": 0,
            "engine_type": "TORRENT",
            "status": "COMPLETED",
            "security_status": "WARNING"
        },
        {
            "id": "t3",
            "filename": "probing.bin",
            "resumable": -1,
            "engine_type": "HTTP",
            "status": "QUEUED",
            "security_status": "UNCHECKED"
        }
    ]

    model.update_tasks(sample_tasks)
    assert model.rowCount() == 3

    # Column 0: Filename
    idx0 = model.index(0, 0)
    assert model.data(idx0) == "sample_movie.mp4"

    # Column 2: Progress UserRole
    idx2 = model.index(0, 2)
    assert model.data(idx2, role=Qt.UserRole) == 50  # 50%

    # Column 5: Resumable indicator + colors
    assert model.data(model.index(0, 5)) == "Yes"
    assert model.data(model.index(0, 5), role=Qt.ForegroundRole).name() == "#10b981"
    assert model.data(model.index(1, 5)) == "No"
    assert model.data(model.index(1, 5), role=Qt.ForegroundRole).name() == "#f59e0b"
    assert model.data(model.index(2, 5)) == "Checking"
    assert model.data(model.index(2, 5), role=Qt.ForegroundRole).name() == "#9ca3af"

    # Column 8: Security Gate
    idx8 = model.index(1, 8)
    assert "Warning" in model.data(idx8)

def test_failed_and_non_completed_tasks_security_badge():
    """
    Verifies that:
    - FAILED tasks display 'Not Scanned' (never 'Clean') with neutral muted gray.
    - PAUSED tasks display 'Not Scanned'.
    - QUEUED and DOWNLOADING tasks display 'Pending'.
    - Only COMPLETED tasks can display 'Clean' or 'Low Warning'.
    """
    model = DownloadTableModel()
    tasks = [
        {
            "id": "t_failed",
            "filename": "broken_download.iso",
            "status": "FAILED",
            "security_status": "CLEAN",  # Even if pre-eval was clean, failed download was not scanned
            "error_message": "HTTP 404 Not Found"
        },
        {
            "id": "t_paused",
            "filename": "paused_file.zip",
            "status": "PAUSED",
            "security_status": "UNCHECKED"
        },
        {
            "id": "t_queued",
            "filename": "queued_file.mp4",
            "status": "QUEUED",
            "security_status": "UNCHECKED"
        },
        {
            "id": "t_downloading",
            "filename": "active_file.bin",
            "status": "DOWNLOADING",
            "security_status": "UNCHECKED"
        },
        {
            "id": "t_completed_clean",
            "filename": "verified_doc.pdf",
            "status": "COMPLETED",
            "security_status": "CLEAN"
        }
    ]
    model.update_tasks(tasks)

    # 1. FAILED task must display "Not Scanned", never "Clean"
    failed_sec = model.data(model.index(0, 8), Qt.DisplayRole)
    assert failed_sec == "Not Scanned"
    assert "Clean" not in failed_sec
    assert model.data(model.index(0, 8), Qt.ForegroundRole).name() == "#9ca3af"

    # 2. PAUSED task must display "Not Scanned"
    paused_sec = model.data(model.index(1, 8), Qt.DisplayRole)
    assert paused_sec == "Not Scanned"
    assert model.data(model.index(1, 8), Qt.ForegroundRole).name() == "#9ca3af"

    # 3. QUEUED and DOWNLOADING tasks must display "Pending"
    queued_sec = model.data(model.index(2, 8), Qt.DisplayRole)
    assert queued_sec == "Pending"

    downloading_sec = model.data(model.index(3, 8), Qt.DisplayRole)
    assert downloading_sec == "Pending"

    # 4. COMPLETED task displays Clean
    completed_sec = model.data(model.index(4, 8), Qt.DisplayRole)
    assert "Clean" in completed_sec
    assert model.data(model.index(4, 8), Qt.ForegroundRole).name() == "#10b981"

def test_engine_manager_task_lifecycle():
    db = Database(":memory:")
    config = Config()
    mgr = EngineManager(config, db)

    task_id = mgr.add_download(
        url="https://example.com/test_archive.zip",
        filename="test_archive.zip",
        destination=config.download_dir,
        num_segments=4
    )

    assert task_id is not None
    task = db.get_task(task_id)
    assert task["filename"] == "test_archive.zip"
    assert task["status"] == "QUEUED"
    assert task["num_segments"] == 4

    # Delete task
    mgr.delete_task(task_id)
    assert db.get_task(task_id) is None
    db.close()

def test_config_persistence(tmp_path):
    cfg_file = tmp_path / "custom_config.json"
    cfg = Config(config_path=cfg_file)
    cfg.max_segments_per_task = 16
    cfg.speed_limit_bytes_per_sec = 1048576
    cfg.save()

    # Re-read
    loaded = Config(config_path=cfg_file)
    assert loaded.max_segments_per_task == 16
    assert loaded.speed_limit_bytes_per_sec == 1048576

def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def test_table_refresh_preserves_multi_selection_and_multi_delete(qt_app, tmp_path):
    """
    Verifies:
    (a) Refreshing table data from DB preserves active multi-row selection
        (both on in-place refreshes and when a new task is added).
    (b) Multi-row delete removes all selected tasks at once.
    """
    db = Database(":memory:")
    cfg = Config(config_path=tmp_path / "cfg.json")
    cfg.download_dir = str(tmp_path / "downloads")
    cfg.staging_dir = str(tmp_path / ".staging")
    cfg.brave_handoff_port = _get_free_port()
    cfg.minimize_to_tray = False
    cfg.notifications_enabled = False

    mgr = EngineManager(cfg, db)
    win = MainWindow(mgr)

    try:
        # Verify multi-select and interactive resizable header configuration
        assert win.table.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection
        assert win.table.selectionBehavior() == QAbstractItemView.SelectionBehavior.SelectRows
        header = win.table.horizontalHeader()
        assert header.stretchLastSection() is False
        for col_idx in range(win.table_model.columnCount()):
            assert header.sectionResizeMode(col_idx) == QHeaderView.ResizeMode.Interactive

        t1 = mgr.add_download("https://example.com/one.zip", filename="one.zip", destination=cfg.download_dir)
        t2 = mgr.add_download("https://example.com/two.zip", filename="two.zip", destination=cfg.download_dir)
        t3 = mgr.add_download("https://example.com/three.zip", filename="three.zip", destination=cfg.download_dir)
        win._refresh_tasks_from_db()

        assert win.table_model.rowCount() == 3

        # Select rows 0 and 2 via QItemSelectionModel
        sel_model = win.table.selectionModel()
        last_col = win.table_model.columnCount() - 1
        selection = QItemSelection()
        selection.select(win.table_model.index(0, 0), win.table_model.index(0, last_col))
        selection.select(win.table_model.index(2, 0), win.table_model.index(2, last_col))
        sel_model.select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

        selected_before = {t["id"] for t in win._get_selected_tasks()}
        assert len(selected_before) == 2

        # 1. Refresh with identical task IDs (simulating 1-second timer tick with progress change)
        db.update_task_progress(t1, 1024, total_bytes=4096, speed_bps=512.0, eta_seconds=6)
        win._refresh_tasks_from_db()
        selected_after_inplace = {t["id"] for t in win._get_selected_tasks()}
        assert selected_after_inplace == selected_before

        # 2. Refresh when a new row is added (structural reset restores selected IDs)
        t4 = mgr.add_download("https://example.com/four.zip", filename="four.zip", destination=cfg.download_dir)
        win._refresh_tasks_from_db()
        assert win.table_model.rowCount() == 4
        selected_after_insert = {t["id"] for t in win._get_selected_tasks()}
        assert selected_after_insert == selected_before

        # 3. Multi-row delete removes all selected tasks
        deleted_count = win.delete_selected_tasks(require_confirmation=False)
        assert deleted_count == 2
        remaining_ids = {t["id"] for t in db.get_all_tasks()}
        assert remaining_ids.isdisjoint(selected_before)
        assert len(remaining_ids) == 2
        assert t4 in remaining_ids
    finally:
        win.clipboard_listener.stop()
        win.force_quit()

def test_add_download_dialog_accepts_http_magnet_and_mega(qt_app, tmp_path):
    """
    Verifies AddDownloadDialog accepts HTTP, Magnet, and MEGA URLs cleanly via Start Download
    without requiring an HTTP probe to succeed first.
    """
    db = Database(":memory:")
    cfg = Config(config_path=tmp_path / "cfg_dlg.json")
    cfg.download_dir = str(tmp_path / "downloads")
    cfg.staging_dir = str(tmp_path / ".staging")
    mgr = EngineManager(cfg, db)

    try:
        # 1. HTTP URL (without waiting on probe)
        dlg_http = AddDownloadDialog(mgr, cfg.download_dir)
        dlg_http.txt_url.setText("https://example.com/ubuntu-24.04.iso")
        dlg_http._on_download()
        assert dlg_http.result_data is not None
        assert dlg_http.result_data["is_torrent"] is False
        assert dlg_http.result_data["url"] == "https://example.com/ubuntu-24.04.iso"
        assert dlg_http.result_data["filename"] == "ubuntu-24.04.iso"

        # 2. Magnet URI
        dlg_mag = AddDownloadDialog(mgr, cfg.download_dir)
        magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Fedora"
        dlg_mag.txt_url.setText(magnet)
        dlg_mag._on_download()
        assert dlg_mag.result_data is not None
        assert dlg_mag.result_data["is_torrent"] is True
        assert dlg_mag.result_data["url"] == magnet

        # 3. MEGA URL
        dlg_mega = AddDownloadDialog(mgr, cfg.download_dir)
        mega_url = "https://mega.nz/file/abc12345#SecretKey123"
        dlg_mega.txt_url.setText(mega_url)
        dlg_mega._on_download()
        assert dlg_mega.result_data is not None
        assert dlg_mega.result_data["is_torrent"] is False
        assert dlg_mega.result_data["url"] == mega_url

        # 4. Pasting an HTTP URL keeps Parallel Connections editable & preserves chosen value
        dlg_conn = AddDownloadDialog(mgr, cfg.download_dir)
        dlg_conn.combo_segments.setCurrentIndex(4)  # User chooses "16 Segments (Max)"
        dlg_conn.txt_url.setText("https://example.com/large_release.zip")
        assert dlg_conn.combo_segments.isEnabled() is True
        assert dlg_conn.combo_segments.currentIndex() == 4
        dlg_conn._on_download()
        assert dlg_conn.result_data is not None
        assert dlg_conn.result_data["num_segments"] == 16
    finally:
        db.close()

def test_http_pause_and_resume_completes_download(qt_app, tmp_path):
    """
    Verifies real HTTP Pause -> Resume workflow via EngineManager:
    - Starts a throttled Range download on HttpDownloadWorker
    - Pauses mid-download and verifies PAUSED status + worker cleanup
    - Resumes the PAUSED task and verifies it completes with exact SHA-256
    """
    payload = b"OmniFetchPauseResumeRealPayload!" * 8192  # ~256 KB
    total_len = len(payload)
    loop = asyncio.new_event_loop()
    server_info = {}

    async def handle_throttled(request):
        if request.method == "HEAD":
            return web.Response(
                status=200,
                headers={
                    "Content-Length": str(total_len),
                    "Accept-Ranges": "bytes",
                    "Content-Disposition": 'attachment; filename="pause_resume_test.bin"'
                }
            )
        start = 0
        end = total_len - 1
        status = 200
        rh = request.headers.get("Range")
        if rh and rh.startswith("bytes="):
            parts = rh.replace("bytes=", "").split("-")
            start = int(parts[0])
            end = int(parts[1]) if parts[1] else total_len - 1
            status = 206
        chunk_data = payload[start:end + 1]
        hdrs = {
            "Content-Length": str(len(chunk_data)),
            "Accept-Ranges": "bytes",
            "Content-Disposition": 'attachment; filename="pause_resume_test.bin"'
        }
        if status == 206:
            hdrs["Content-Range"] = f"bytes {start}-{end}/{total_len}"
        resp = web.StreamResponse(status=status, headers=hdrs)
        await resp.prepare(request)
        for i in range(0, len(chunk_data), 16384):
            await resp.write(chunk_data[i:i + 16384])
            await asyncio.sleep(0.03)
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route("*", "/throttled", handle_throttled)
    runner = web.AppRunner(app)

    def run_srv():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port = site._server.sockets[0].getsockname()[1]
        server_info["url"] = f"http://127.0.0.1:{port}/throttled"
        server_info["ready"] = True
        loop.run_forever()

    srv_thread = threading.Thread(target=run_srv, daemon=True)
    srv_thread.start()
    while "ready" not in server_info:
        time.sleep(0.02)

    db = Database(":memory:")
    cfg = Config(config_path=tmp_path / "cfg_pr.json")
    cfg.download_dir = str(tmp_path / "downloads")
    cfg.staging_dir = str(tmp_path / ".staging")
    cfg.cybershield_enabled = False
    mgr = EngineManager(cfg, db)

    try:
        task_id = mgr.add_download(
            url=server_info["url"],
            filename="download.bin",
            destination=cfg.download_dir,
            num_segments=1
        )
        mgr.start_download(task_id)

        # Wait for progress before pausing
        deadline = time.time() + 5.0
        while time.time() < deadline:
            qt_app.processEvents()
            t = db.get_task(task_id)
            if t["downloaded_bytes"] >= 16384:
                break
            time.sleep(0.05)

        mgr.pause_download(task_id)
        deadline = time.time() + 4.0
        while time.time() < deadline:
            qt_app.processEvents()
            t = db.get_task(task_id)
            if t["status"] == "PAUSED" and task_id not in mgr.active_workers:
                break
            time.sleep(0.05)

        paused_task = db.get_task(task_id)
        assert paused_task["status"] == "PAUSED"
        assert task_id not in mgr.active_workers

        # Now resume and wait for COMPLETED
        mgr.resume_download(task_id)
        deadline = time.time() + 8.0
        while time.time() < deadline:
            qt_app.processEvents()
            t = db.get_task(task_id)
            if t["status"] == "COMPLETED":
                break
            time.sleep(0.05)

        done_task = db.get_task(task_id)
        assert done_task["status"] == "COMPLETED"
        assert done_task["resumable"] == 1
        final_file = tmp_path / "downloads" / "pause_resume_test.bin"
        assert final_file.exists()
        assert hashlib.sha256(final_file.read_bytes()).hexdigest() == hashlib.sha256(payload).hexdigest()
    finally:
        mgr.shutdown()
        loop.call_soon_threadsafe(loop.stop)
