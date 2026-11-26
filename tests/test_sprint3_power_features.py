"""
Sprint 3 (P2 Power Features & Polish) Non-Mocked Integration Tests:
1. Orphan .staging/ Garbage Collector (preserves active DB task dirs & _metadata_cache).
2. Live libtorrent 2.1.1.0 session.apply_settings() across port, DHT, LSD, UPnP, enc_policy, and limits.
3. Safe Post-Stage-3 Archive Auto-Extract + Zip-Slip traversal block + Stage 3 verdict enforcement +
   post-extraction CyberShield EICAR quarantine.
4. Queue Scheduler window (same-day + overnight wrap-around) + 1-Click Pairing (/api/pair origin/window security)
   + Double-click single-file vs folder routing + Browser extension manifest/sniffer verification.
"""

import hashlib
import io
import json
import os
import socket
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

import libtorrent as lt
import pytest
from PySide6.QtWidgets import QApplication

from app.core.archive_extractor import SafeArchiveExtractor, ZipSlipError
from app.core.config import Config
from app.core.db import Database
from app.core.engine_manager import EngineManager
from app.core.scheduler import DownloadScheduler, is_within_schedule
from app.core.security_gate import SecurityGate
from app.core.staging import StagingManager
from app.engines.torrent.session import TorrentSessionManager
from app.integrations.browser_bridge import BrowserHandoffBridge
from app.ui.main_window import MainWindow
from app.ui.settings_dialog import SettingsDialog


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


def _make_cfg(tmp_path: Path, name: str = "cfg.json", cybershield: bool = False) -> Config:
    cfg = Config(config_path=tmp_path / name)
    cfg.download_dir = str(tmp_path / "downloads")
    cfg.staging_dir = str(tmp_path / ".staging")
    cfg.cybershield_enabled = cybershield
    cfg.minimize_to_tray = False
    cfg.notifications_enabled = False
    return cfg


# ---------------------------------------------------------------------------
# TEST 1: Orphan .staging/ Garbage Collector
# ---------------------------------------------------------------------------
def test_1_orphan_staging_gc_preserves_active_and_metadata(tmp_path):
    cfg = _make_cfg(tmp_path, "gc_cfg.json")
    db = Database(db_path=str(tmp_path / "gc.db"))
    mgr = EngineManager(cfg, db)

    try:
        sm = mgr.staging
        active_id = mgr.add_download("https://example.com/keep.bin", filename="keep.bin")
        active_dir = sm.allocate_task_staging(active_id)
        (active_dir / "segment_0.part").write_bytes(b"KEEP_ME" * 100)

        meta_cache = Path(cfg.staging_dir) / "_metadata_cache"
        meta_cache.mkdir(parents=True, exist_ok=True)
        (meta_cache / "deadbeef.torrent").write_bytes(b"TORRENT_META")

        orphan_old = Path(cfg.staging_dir) / "orphan99"
        orphan_old.mkdir(parents=True, exist_ok=True)
        stale_part = orphan_old / "segment_0.part"
        stale_part.write_bytes(b"Z" * 8192)
        stale_ts = time.time() - 7200  # 2 hours old
        os.utime(stale_part, (stale_ts, stale_ts))
        os.utime(orphan_old, (stale_ts, stale_ts))

        orphan_fresh = Path(cfg.staging_dir) / "fresh_orphan"
        orphan_fresh.mkdir(parents=True, exist_ok=True)
        (orphan_fresh / "segment_0.part").write_bytes(b"N" * 1024)

        # Automatic policy (min_age_seconds=3600) deletes only orphan_old
        res_auto = mgr.clean_orphaned_staging(min_age_seconds=3600)
        assert res_auto["removed_count"] == 1
        assert res_auto["removed_ids"] == ["orphan99"]
        assert res_auto["reclaimed_bytes"] >= 8192
        assert not orphan_old.exists()
        assert orphan_fresh.exists()
        assert active_dir.exists()
        assert meta_cache.exists()

        # Manual clean (min_age_seconds=0) removes remaining orphan_fresh while keeping active + _metadata_cache
        res_manual = mgr.clean_orphaned_staging(min_age_seconds=0)
        assert res_manual["removed_count"] == 1
        assert res_manual["removed_ids"] == ["fresh_orphan"]
        assert not orphan_fresh.exists()
        assert (active_dir / "segment_0.part").exists()
        assert (meta_cache / "deadbeef.torrent").exists()
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------------------
# TEST 2: Real libtorrent 2.1.1.0 Session Settings & Config Persistence
# ---------------------------------------------------------------------------
def test_2_real_libtorrent_apply_settings_and_settings_dialog_persistence(tmp_path, qt_app):
    cfg_path = tmp_path / "bt_cfg.json"
    cfg = _make_cfg(tmp_path, "bt_cfg.json")
    db = Database(db_path=str(tmp_path / "bt.db"))
    mgr = EngineManager(cfg, db)

    try:
        dlg = SettingsDialog(cfg, engine_manager=mgr)
        dlg.spin_bt_port.setValue(0)  # Random ephemeral port
        idx_req = dlg.combo_bt_enc.findData("require")
        dlg.combo_bt_enc.setCurrentIndex(idx_req)
        dlg.chk_bt_dht.setChecked(False)
        dlg.chk_bt_pex.setChecked(False)
        dlg.chk_bt_upnp.setChecked(False)
        dlg.spin_bt_conns.setValue(120)
        dlg.spin_bt_peers.setValue(35)
        dlg.spin_ratio.setValue(1.5)
        dlg.chk_auto_extract.setChecked(True)
        dlg._save_settings()

        # Verify Config persisted cleanly
        reloaded = Config(config_path=cfg_path)
        assert reloaded.bt_listen_port == 0
        assert reloaded.bt_encryption_mode == "require"
        assert reloaded.bt_enable_dht is False
        assert reloaded.bt_enable_pex_lsd is False
        assert reloaded.bt_enable_upnp is False
        assert reloaded.bt_max_connections == 120
        assert reloaded.bt_max_peers_per_torrent == 35
        assert reloaded.seeding_ratio_cutoff == 1.5
        assert reloaded.auto_extract_archives is True

        # Verify live libtorrent session accepted all settings cleanly without errors
        live_settings = mgr.torrent_session.ses.get_settings()
        assert live_settings["listen_interfaces"] == "0.0.0.0:0,[::]:0"
        assert live_settings["enable_dht"] is False
        assert live_settings["enable_lsd"] is False
        assert live_settings["enable_upnp"] is False
        assert live_settings["enable_natpmp"] is False
        assert live_settings["in_enc_policy"] == int(lt.enc_policy.pe_forced)
        assert live_settings["out_enc_policy"] == int(lt.enc_policy.pe_forced)
        assert live_settings["connections_limit"] == 120
        assert mgr.torrent_session._max_peers_per_torrent == 35
    finally:
        mgr.shutdown()


# ---------------------------------------------------------------------------
# TEST 3: Safe Archive Auto-Extract, Zip-Slip Block & EICAR Post-Extract Scan
# ---------------------------------------------------------------------------
def test_3_safe_archive_extractor_security_guardrails(tmp_path):
    cfg = _make_cfg(tmp_path, "arc_cfg.json", cybershield=True)
    db = Database(db_path=str(tmp_path / "arc.db"))
    sm = StagingManager(cfg.staging_dir)
    gate = SecurityGate(db=db, staging_manager=sm)

    try:
        # 1. Clean ZIP extraction succeeds only when Stage 3 verdict == MOVED_CLEAN
        clean_zip = tmp_path / "clean_docs.zip"
        with zipfile.ZipFile(clean_zip, "w") as zf:
            zf.writestr("readme.txt", "Safe Sprint 3 text payload")
            zf.writestr("nested/data.json", '{"ok": true}')

        # Must refuse extraction on QUARANTINED / MOVED_WARNING / SCAN_ERROR verdicts
        for blocked_action, blocked_sev in [("QUARANTINED", "CRITICAL"), ("MOVED_WARNING", "LOW"), ("SCAN_ERROR", "SCAN_ERROR")]:
            refused = SafeArchiveExtractor.extract_and_scan(
                clean_zip,
                {"action": blocked_action, "severity": blocked_sev},
                security_gate=gate,
            )
            assert refused["extracted"] is False

        ok_res = SafeArchiveExtractor.extract_and_scan(
            clean_zip,
            {"action": "MOVED_CLEAN", "severity": "CLEAN"},
            security_gate=gate,
        )
        assert ok_res["extracted"] is True
        assert ok_res["extracted_count"] == 2
        assert (tmp_path / "clean_docs" / "readme.txt").read_text() == "Safe Sprint 3 text payload"

        # 2. Zip-Slip path traversal in ZIP must be blocked before writing anything outside
        evil_zip = tmp_path / "zipslip.zip"
        with zipfile.ZipFile(evil_zip, "w") as zf:
            zf.writestr("../../escaped_evil.txt", "pwned")
        with pytest.raises(ZipSlipError):
            SafeArchiveExtractor.extract_and_scan(
                evil_zip,
                {"action": "MOVED_CLEAN", "severity": "CLEAN"},
                security_gate=gate,
            )
        assert not (tmp_path / "escaped_evil.txt").exists()

        # 3. Tar symlink / traversal block
        evil_tar = tmp_path / "slip.tar.gz"
        with tarfile.open(evil_tar, "w:gz") as tf:
            ti = tarfile.TarInfo("../outside.sh")
            data = b"#!/bin/sh\necho bad\n"
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        with pytest.raises(ZipSlipError):
            SafeArchiveExtractor.extract_and_scan(
                evil_tar,
                {"action": "MOVED_CLEAN", "severity": "CLEAN"},
                security_gate=gate,
            )

        # 4. Critical payload (EICAR inside .exe) hidden inside a CLEAN-container .zip is quarantined post-extract
        tid_arc = "arc0001"
        db.add_task({
            "id": tid_arc,
            "url": "https://example.com/bundle.zip",
            "filename": "bundle.zip",
            "destination": cfg.download_dir,
            "staging_path": str(sm.allocate_task_staging(tid_arc)),
            "engine_type": "HTTP",
            "status": "COMPLETED",
        })
        eicar_str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        trojan_zip = tmp_path / "bundle.zip"
        with zipfile.ZipFile(trojan_zip, "w") as zf:
            zf.writestr("notes.txt", "Normal readme")
            zf.writestr("payload_setup.exe", eicar_str)

        res_q = SafeArchiveExtractor.extract_and_scan(
            trojan_zip,
            {"action": "MOVED_CLEAN", "severity": "CLEAN"},
            security_gate=gate,
            db=db,
            task_id=tid_arc,
        )
        assert res_q["extracted"] is True
        assert len(res_q["quarantined_files"]) == 1
        assert not (tmp_path / "bundle" / "payload_setup.exe").exists()
        audits = db.get_security_audit(tid_arc)
        assert any(a["verdict"] == "BLOCK_CRITICAL" for a in audits)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TEST 4: Queue Scheduler Window, 1-Click Pairing Security, Double-Click & Extension
# ---------------------------------------------------------------------------
def test_4_scheduler_window_1click_pairing_doubleclick_and_extension(tmp_path, qt_app):
    # 1. Daily Queue Schedule Window logic (same-day + overnight wrap-around)
    assert is_within_schedule("09:00", "17:00", datetime(2026, 11, 26, 12, 30)) is True
    assert is_within_schedule("09:00", "17:00", datetime(2026, 11, 26, 20, 0)) is False
    assert is_within_schedule("23:00", "06:00", datetime(2026, 11, 26, 23, 45)) is True
    assert is_within_schedule("23:00", "06:00", datetime(2026, 11, 27, 2, 15)) is True
    assert is_within_schedule("23:00", "06:00", datetime(2026, 11, 27, 14, 0)) is False

    cfg = _make_cfg(tmp_path, "sched_cfg.json")
    cfg.brave_handoff_port = _free_port()
    cfg.brave_handoff_token = "sprint3_pair_secret_token"
    cfg.schedule_enabled = True
    cfg.schedule_start_time = "09:00"
    cfg.schedule_stop_time = "17:00"

    db = Database(db_path=str(tmp_path / "sched.db"))
    mgr = EngineManager(cfg, db)
    scheduler = DownloadScheduler()

    try:
        tid_q = mgr.add_download("https://example.com/paused.bin", filename="paused.bin")
        db.update_task_status(tid_q, "PAUSED")

        # Outside window -> evaluates PAUSED transition
        assert scheduler.evaluate_tick(mgr, cfg, datetime(2026, 11, 26, 22, 0)) == "PAUSED"
        # Inside window -> resumes queued/paused task cleanly
        assert scheduler.evaluate_tick(mgr, cfg, datetime(2026, 11, 26, 10, 0)) == "RESUMED"
        mgr.pause_download(tid_q)

        # 2. Safe 1-Click Pairing on BrowserHandoffBridge (/api/pair)
        bridge = BrowserHandoffBridge(cfg, mgr)
        assert bridge.start()
        time.sleep(0.15)
        try:
            pair_url = f"http://127.0.0.1:{cfg.brave_handoff_port}/api/pair"

            # Reject when pairing window is closed -> 403
            req_closed = urllib.request.Request(
                pair_url, data=b"{}", headers={"Origin": "chrome-extension://abcdefghijklmnop"}, method="POST"
            )
            with pytest.raises(urllib.error.HTTPError) as e_closed:
                urllib.request.urlopen(req_closed)
            assert e_closed.value.code == 403

            # Open 60s pairing window, verify non-extension website origin STILL gets 403
            bridge.open_pairing_window(60)
            assert bridge.is_pairing_open() is True
            req_bad_origin = urllib.request.Request(
                pair_url, data=b"{}", headers={"Origin": "https://evil.example.com"}, method="POST"
            )
            with pytest.raises(urllib.error.HTTPError) as e_orig:
                urllib.request.urlopen(req_bad_origin)
            assert e_orig.value.code == 403

            # Valid chrome-extension:// origin succeeds ONCE and immediately auto-closes window
            req_ok = urllib.request.Request(
                pair_url, data=b"{}", headers={"Origin": "chrome-extension://omnifetchhelper123"}, method="POST"
            )
            with urllib.request.urlopen(req_ok) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["token"] == cfg.brave_handoff_token
                assert data["port"] == cfg.brave_handoff_port
            assert bridge.is_pairing_open() is False

            # Replay attempt fails 403 because window was single-use
            with pytest.raises(urllib.error.HTTPError) as e_replay:
                urllib.request.urlopen(req_ok)
            assert e_replay.value.code == 403
        finally:
            bridge.stop()

        # 3. Double-click path helper: single completed file resolves to file; multi-file resolves to None (folder)
        dest_dir = Path(cfg.download_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        single_file = dest_dir / "report.pdf"
        single_file.write_bytes(b"%PDF-1.4\n")
        multi_dir = dest_dir / "MoviePack"
        multi_dir.mkdir(parents=True, exist_ok=True)

        win = MainWindow(mgr)
        win.refresh_timer.stop()
        win.schedule_timer.stop()
        win.browser_bridge.stop()
        try:
            t_single = {"status": "COMPLETED", "destination": str(dest_dir), "filename": "report.pdf"}
            t_multi = {"status": "COMPLETED", "destination": str(dest_dir), "filename": "MoviePack"}
            t_paused = {"status": "PAUSED", "destination": str(dest_dir), "filename": "report.pdf"}
            assert win._get_completed_single_file_path(t_single) == single_file
            assert win._get_completed_single_file_path(t_multi) is None
            assert win._get_completed_single_file_path(t_paused) is None
        finally:
            win.clipboard_listener.stop()
            win.force_quit()

        # 4. Verify Brave extension manifest & popup include webRequest media sniffer + /api/pair Auto-Pair
        manifest = json.loads(Path(r"C:\Users\shrey\Desktop\OmniFetch\browser_extension\manifest.json").read_text(encoding="utf-8"))
        assert "webRequest" in manifest["permissions"]
        assert "tabs" in manifest["permissions"]
        popup_js = Path(r"C:\Users\shrey\Desktop\OmniFetch\browser_extension\popup.js").read_text(encoding="utf-8")
        assert "/api/pair" in popup_js
        assert "getTabMedia" in popup_js
    finally:
        mgr.shutdown()
