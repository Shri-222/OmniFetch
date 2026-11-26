"""
OmniFetch v1.0 Gold Master Integration Tests:
1. Live Task Visibility Bug Fix: HTTP, Torrent, MEGA, and Browser /api/handoff tasks appear
   immediately in live QTableView within 1 Qt event tick (All Downloads & Downloading filters).
2. Live Search, Engine Filter Pills, Smart Categories, Sortable Columns, and Selection Preservation.
3. Queue Priority (force_start_task, move_to_top), Smart Delete (delete_files=False vs True), and Disk Space Guard.
4. Batch Link Import + Stage 1 Trap Filtering, Inspector SHA-256 Verifier, Auto-Categorize, and FFmpeg HLS builder/fallback.
"""

import hashlib
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path

import libtorrent as lt
import pytest
from PySide6.QtCore import Qt, QItemSelection, QItemSelectionModel
from PySide6.QtWidgets import QApplication

from app.core.config import Config
from app.core.db import Database
from app.core.engine_manager import EngineManager
from app.engines.http.hls_remuxer import HlsRemuxWorker, build_ffmpeg_hls_command, is_hls_url
from app.ui.add_dialog import AddDownloadDialog, parse_batch_links_text
from app.ui.inspector_drawer import TaskInspectorDrawer
from app.ui.main_window import MainWindow


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_cfg(tmp_path: Path, name: str = "gm_cfg.json") -> Config:
    cfg = Config(config_path=tmp_path / name)
    cfg.download_dir = str(tmp_path / "downloads")
    cfg.staging_dir = str(tmp_path / ".staging")
    cfg.cybershield_enabled = False
    cfg.minimize_to_tray = False
    cfg.notifications_enabled = False
    cfg.brave_handoff_port = _free_port()
    cfg.brave_handoff_token = "gm_test_token"
    return cfg


def _pump_qt(qt_app, iterations: int = 8):
    for _ in range(iterations):
        qt_app.processEvents()
        time.sleep(0.01)


# ---------------------------------------------------------------------------
# TEST 1: Live Visibility Bug Fix Across HTTP, Torrent, MEGA & Brave Handoff
# ---------------------------------------------------------------------------
def test_1_live_visibility_immediately_updates_table(tmp_path, qt_app):
    cfg = _make_cfg(tmp_path, "vis.json")
    db = Database(db_path=str(tmp_path / "vis.db"))
    mgr = EngineManager(cfg, db)
    win = MainWindow(mgr)
    win.refresh_timer.stop()  # Prove signals alone drive live visibility without 1s polling!
    win.schedule_timer.stop()

    try:
        # 1. Start on Downloading tab (which previously hid QUEUED tasks)
        win.sidebar.setCurrentRow(1)
        _pump_qt(qt_app)
        assert win.current_filter == "Downloading"
        assert win.table_model.rowCount() == 0

        # Add HTTP task (status=QUEUED initially -> MUST appear in Downloading immediately!)
        t_http = mgr.add_download("https://example.com/movie.mp4", filename="movie.mp4", destination=cfg.download_dir)
        _pump_qt(qt_app)
        assert win.table_model.rowCount() == 1
        assert win.table_model.tasks[0]["id"] == t_http

        # Add Torrent task using dummy torrent_info
        src_dir = tmp_path / "t_src"
        src_dir.mkdir()
        (src_dir / "track.mkv").write_bytes(b"MKV_DATA" * 2048)
        fl = lt.list_files(str(src_dir))
        ct = lt.create_torrent(fl, 16384, flags=lt.create_torrent.v1_only)
        lt.set_piece_hashes(ct, str(tmp_path))
        ti = lt.torrent_info(lt.bdecode(lt.bencode(ct.generate())))
        t_tor = mgr.add_torrent_download(ti, "LiveTorrentPack", cfg.download_dir, file_priorities=[4])
        _pump_qt(qt_app)
        assert win.table_model.rowCount() == 2
        mgr.pause_download(t_tor)

        # Add MEGA task
        t_mega = mgr.add_mega_download("https://mega.nz/file/LiveVis1#SecretKey12345678901234", filename="mega_pack.zip")
        _pump_qt(qt_app)

        # Switch to All Downloads and submit a Brave Bridge POST /api/handoff from background thread
        win.sidebar.setCurrentRow(0)
        _pump_qt(qt_app)
        assert win.table_model.rowCount() == 3

        req = urllib.request.Request(
            f"http://127.0.0.1:{cfg.brave_handoff_port}/api/handoff",
            data=json.dumps({"url": "https://cdn.example/installer.exe", "filename": "installer.exe"}).encode(),
            headers={"X-OmniFetch-Token": cfg.brave_handoff_token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            handoff_id = json.loads(resp.read().decode())["task_id"]

        # Within Qt event ticks (zero restart, refresh_timer stopped!), row appears immediately!
        for _ in range(30):
            qt_app.processEvents()
            if any(t["id"] == handoff_id for t in win.table_model.tasks):
                break
            time.sleep(0.02)

        assert win.table_model.rowCount() == 4
        assert any(t["id"] == handoff_id for t in win.table_model.tasks)
    finally:
        win.clipboard_listener.stop()
        win.force_quit()


# ---------------------------------------------------------------------------
# TEST 2: Search, Engine Pills, Smart Categories, Sorting & Selection Retention
# ---------------------------------------------------------------------------
def test_2_search_categories_sorting_and_selection_preservation(tmp_path, qt_app):
    cfg = _make_cfg(tmp_path, "filter.json")
    db = Database(db_path=str(tmp_path / "filter.db"))
    mgr = EngineManager(cfg, db)
    win = MainWindow(mgr)
    win.refresh_timer.stop()
    win.schedule_timer.stop()
    win.browser_bridge.stop()

    try:
        t1 = mgr.add_download("https://a.example/alpha_video.mp4", filename="alpha_video.mp4")
        t2 = mgr.add_download("https://b.example/beta_archive.zip", filename="beta_archive.zip")
        t3 = mgr.add_download("https://c.example/gamma_setup.exe", filename="gamma_setup.exe")
        db.update_task_progress(t1, 100, total_bytes=5000)
        db.update_task_progress(t2, 200, total_bytes=1000)
        db.update_task_progress(t3, 300, total_bytes=3000)
        db.update_task_status(t2, "COMPLETED")
        win._refresh_tasks_from_db()
        assert win.table_model.rowCount() == 3

        # 1. Search filter
        win.txt_search.setText("beta")
        assert win.table_model.rowCount() == 1
        assert win.table_model.tasks[0]["id"] == t2
        win.txt_search.clear()
        assert win.table_model.rowCount() == 3

        # 2. Smart Category filter
        win.set_category_filter("Videos")
        assert [t["id"] for t in win.table_model.tasks] == [t1]
        win.set_category_filter(None)

        # 3. Engine Pill filter
        win.set_engine_filter("TORRENT")
        assert win.table_model.rowCount() == 0
        win.set_engine_filter("ALL")
        assert win.table_model.rowCount() == 3

        # 4. Sortable column ordering (Size ascending -> 1000, 3000, 5000)
        win.table.sortByColumn(1, Qt.AscendingOrder)
        assert [t["id"] for t in win.table_model.tasks] == [t2, t3, t1]

        # 5. Multi-row selection stays intact across sorted refresh + live task insertion
        sel_model = win.table.selectionModel()
        last_col = win.table_model.columnCount() - 1
        selection = QItemSelection()
        selection.select(win.table_model.index(0, 0), win.table_model.index(0, last_col))
        selection.select(win.table_model.index(2, 0), win.table_model.index(2, last_col))
        sel_model.select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
        selected_ids_before = {t["id"] for t in win._get_selected_tasks()}
        assert selected_ids_before == {t2, t1}

        t4 = mgr.add_download("https://d.example/delta_doc.pdf", filename="delta_doc.pdf")
        db.update_task_progress(t4, 0, total_bytes=4000)
        win._refresh_tasks_from_db()
        assert win.table_model.rowCount() == 4
        assert {t["id"] for t in win._get_selected_tasks()} == selected_ids_before
    finally:
        win.clipboard_listener.stop()
        win.force_quit()


# ---------------------------------------------------------------------------
# TEST 3: Queue Priority (Force Start / Move to Top), Smart Delete & Disk Guard
# ---------------------------------------------------------------------------
def test_3_queue_priority_smart_delete_and_disk_guard(tmp_path):
    cfg = _make_cfg(tmp_path, "prio.json")
    cfg.max_concurrent_tasks = 1
    db = Database(db_path=str(tmp_path / "prio.db"))
    mgr = EngineManager(cfg, db)

    try:
        # Simulate max_concurrent_tasks saturation with 3 queued tasks
        t1 = mgr.add_download("https://example.com/one.bin", filename="one.bin")
        t2 = mgr.add_download("https://example.com/two.bin", filename="two.bin")
        t3 = mgr.add_download("https://example.com/three.bin", filename="three.bin")
        mgr._pending_queue = [t1, t2, t3]

        assert mgr.move_to_top(t3) is True
        assert mgr._pending_queue[0] == t3

        # force_start_task bypasses max_concurrent_tasks even if a fake running worker holds the slot
        class _DummyRunning:
            def isRunning(self): return True
            def stop(self): pass
            def pause(self): pass
            def cancel(self): pass
            def wait(self, ms): pass

        mgr.active_workers["blocker"] = _DummyRunning()
        assert mgr.force_start_task(t2) is True
        assert t2 not in mgr._pending_queue
        assert t2 in mgr.active_workers
        mgr.pause_download(t2)
        mgr.active_workers.pop("blocker", None)

        # Smart Delete: delete_files=False keeps final destination file, removes DB & staging
        dest_dir = Path(cfg.download_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        keep_file = dest_dir / "keep_me.zip"
        keep_file.write_bytes(b"FINAL_DATA")
        t_keep = mgr.add_download("https://example.com/keep_me.zip", filename="keep_me.zip", destination=str(dest_dir))
        db.update_task_status(t_keep, "COMPLETED")
        mgr.delete_task(t_keep, delete_files=False)
        assert db.get_task(t_keep) is None
        assert keep_file.exists()

        # Smart Delete: delete_files=True deletes final destination file & staging too
        del_file = dest_dir / "delete_me.zip"
        del_file.write_bytes(b"DELETE_DATA")
        t_del = mgr.add_download("https://example.com/delete_me.zip", filename="delete_me.zip", destination=str(dest_dir))
        db.update_task_status(t_del, "COMPLETED")
        mgr.delete_task(t_del, delete_files=True)
        assert db.get_task(t_del) is None
        assert not del_file.exists()

        # Disk Space Guard catches impossibly large files cleanly
        huge_check = mgr.check_disk_space(cfg.download_dir, 1024 ** 6)  # 1 Exabyte
        assert huge_check["ok"] is False
        assert "Insufficient disk space" in huge_check["message"]
        small_check = mgr.check_disk_space(cfg.download_dir, 1024 * 1024)
        assert small_check["ok"] is True
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------------------
# TEST 4: Batch Import, SHA-256 Verifier, Auto-Categorize & HLS Builder
# ---------------------------------------------------------------------------
def test_4_batch_import_sha256_autocategorize_and_hls(tmp_path, qt_app, monkeypatch):
    cfg = _make_cfg(tmp_path, "gm4.json")
    cfg.auto_categorize_folders = True
    db = Database(db_path=str(tmp_path / "gm4.db"))
    mgr = EngineManager(cfg, db)

    try:
        # 1. Batch Links parser + Stage 1 trap rejection in AddDownloadDialog
        batch_text = (
            "https://example.com/alpha.mp4\n"
            "https://bad.example/invoice.pdf.exe\n"
            "https://mega.nz/file/AbCd1234#ValidKeyHere12345678901\n"
        )
        parsed = parse_batch_links_text(batch_text)
        assert len(parsed) == 3

        dlg = AddDownloadDialog(mgr, cfg.download_dir)
        dlg.set_batch_text(batch_text)
        assert dlg.batch_table.rowCount() == 3
        # Critical trap must be auto-unchecked & disabled; safe HTTP/MEGA stay checked
        assert dlg._batch_checkboxes[0].isChecked() is True
        assert dlg._batch_checkboxes[1].isChecked() is False
        assert dlg._batch_checkboxes[1].isEnabled() is False
        assert dlg._batch_checkboxes[2].isChecked() is True

        # 2. Optional Auto-Categorize Subfolders
        t_vid = mgr.add_download("https://example.com/clip.mkv", filename="clip.mkv", destination=cfg.download_dir)
        assert Path(db.get_task(t_vid)["destination"]).name == "Videos"

        # 3. Inspector SHA-256 Verifier + SegmentStripWidget
        out_dir = Path(cfg.download_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        verified_file = out_dir / "verified_pack.zip"
        raw = b"OMNIFETCH_SHA256_CHECK_BYTES_" * 400
        verified_file.write_bytes(raw)
        real_sha = hashlib.sha256(raw).hexdigest()

        tid_v = "sha_ver_1"
        db.add_task({
            "id": tid_v,
            "url": "https://example.com/verified_pack.zip",
            "filename": "verified_pack.zip",
            "destination": str(out_dir),
            "staging_path": str(mgr.staging.allocate_task_staging(tid_v)),
            "engine_type": "HTTP",
            "status": "COMPLETED",
            "total_bytes": len(raw),
            "downloaded_bytes": len(raw),
            "resumable": 1,
        })
        db.save_segments(tid_v, [{"index": 0, "start": 0, "end": len(raw) - 1, "current": len(raw), "status": "COMPLETED"}])

        drawer = TaskInspectorDrawer()
        drawer.update_for_task(db.get_task(tid_v), mgr)
        assert drawer.txt_sha256.text() == real_sha
        drawer.txt_expected_sha.setText(real_sha)
        assert drawer.lbl_sha_status.text() == "Verified Match"
        drawer.txt_expected_sha.setText("0" * 64)
        assert drawer.lbl_sha_status.text() == "Hash Mismatch"
        drawer.segment_strip.repaint()

        # 4. HLS .m3u8 detection, FFmpeg header CLI builder & graceful missing-ffmpeg fallback
        assert is_hls_url("https://cdn.example/live/playlist.m3u8?token=xyz") is True
        assert is_hls_url("https://cdn.example/video.mp4") is False
        cmd = build_ffmpeg_hls_command(
            "ffmpeg",
            "https://cdn.example/stream.m3u8",
            str(tmp_path / "out.mp4"),
            custom_headers={"User-Agent": "BraveTest/1.0", "Referer": "https://player.example/", "Cookie": "sid=99"},
        )
        assert "-user_agent" in cmd and "BraveTest/1.0" in cmd
        assert "-headers" in cmd
        hdr_arg = cmd[cmd.index("-headers") + 1]
        assert "Referer: https://player.example/" in hdr_arg
        assert "Cookie: sid=99" in hdr_arg
        assert str(tmp_path / "out.mp4") in cmd

        monkeypatch.setattr("app.engines.http.hls_remuxer.find_ffmpeg", lambda: None)
        t_hls = mgr.add_download("https://cdn.example/missing_ffmpeg.m3u8", filename="stream.m3u8")
        worker = HlsRemuxWorker(t_hls, db, mgr.staging, None)
        worker.run()
        t_hls_row = db.get_task(t_hls)
        assert t_hls_row["status"] == "FAILED"
        assert "FFmpeg not found" in (t_hls_row.get("error_message") or "")
    finally:
        mgr.shutdown()
