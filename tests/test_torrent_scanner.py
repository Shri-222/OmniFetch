"""
Tests for BitTorrent / Magnet Engine, Smart Threat Inspector, and Stage 3 Gate
Verifies:
- parse_magnet_uri with zero-payload inspection flags.
- Smart Threat Inspector (media torrent traps auto-unchecked vs game installers kept checked).
- Selective file priorities mapping.
- Fast-resume data buffer round-trip.
- Stage 3 per-file post-download inspection & CyberShield quarantine isolation.
"""

import os
import time
import shutil
import tempfile
import pytest
from pathlib import Path
import libtorrent as lt

from app.engines.torrent.file_tree import TorrentFileInspector
from app.engines.torrent.session import (
    TorrentSessionManager,
    DHT_BOOTSTRAP_ROUTERS,
    PUBLIC_FALLBACK_TRACKERS,
)
from app.engines.torrent.worker import TorrentDownloadWorker
from app.core.db import Database
from app.core.staging import StagingManager
from app.core.security_gate import SecurityGate

@pytest.fixture
def temp_torrent_env():
    tmp = tempfile.mkdtemp(prefix="omnifetch_torrent_test_")
    staging_dir = Path(tmp) / ".staging"
    dest_dir = Path(tmp) / "downloads"
    staging_dir.mkdir(parents=True, exist_ok=True)
    dest_dir.mkdir(parents=True, exist_ok=True)
    db = Database(":memory:")
    sm = StagingManager(staging_dir)
    gate = SecurityGate(db=db, staging_manager=sm)
    yield db, sm, gate, staging_dir, dest_dir
    db.close()
    shutil.rmtree(tmp, ignore_errors=True)

def test_parse_magnet_uri_zero_payload_flags(tmp_path):
    magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Ubuntu_Test"
    mgr = TorrentSessionManager(tmp_path / ".staging")
    params = mgr.build_magnet_metadata_params(magnet)

    assert isinstance(params, lt.add_torrent_params)
    assert params.name == "Ubuntu_Test"

    # Verify qBittorrent zero-payload metadata pattern:
    # stop_when_ready, auto_managed, and paused MUST NOT be set;
    # upload_mode and default_dont_download MUST be set.
    assert not bool(params.flags & lt.torrent_flags.stop_when_ready)
    assert not bool(params.flags & lt.torrent_flags.auto_managed)
    assert not bool(params.flags & lt.torrent_flags.paused)
    assert bool(params.flags & lt.torrent_flags.upload_mode)
    assert bool(params.flags & lt.torrent_flags.default_dont_download)
    assert len(params.file_priorities) == 1000
    assert all(p == 0 for p in params.file_priorities)

    # Verify DHT enabled & bootstrap routers + fallback public trackers configured
    ses_settings = mgr.ses.get_settings()
    assert ses_settings.get("enable_dht") is True
    bootstrap_str = ses_settings.get("dht_bootstrap_nodes", "")
    for host, port in DHT_BOOTSTRAP_ROUTERS:
        assert f"{host}:{port}" in bootstrap_str
    for tracker in PUBLIC_FALLBACK_TRACKERS:
        assert tracker in list(params.trackers)

def test_fast_resume_data_buffer_roundtrip():
    params = lt.add_torrent_params()
    params.name = "ResumeTest"
    buf = lt.write_resume_data_buf(params)
    assert len(buf) > 0

    restored = lt.read_resume_data(buf)
    assert isinstance(restored, lt.add_torrent_params)
    assert restored.name == "ResumeTest"

def test_smart_inspector_media_torrent_with_traps():
    """
    In a movie torrent, any double-extension (.mp4.exe), .scr, or tiny .exe
    must be AUTO-UNCHECKED (priority 0) with CRITICAL severity.
    """
    mock_files = [
        {"index": 0, "path": "Avatar.2026.1080p.mkv", "size": 3_500_000_000},
        {"index": 1, "path": "Avatar.2026.1080p.srt", "size": 85_000},
        {"index": 2, "path": "Sample.mp4", "size": 15_000_000},
        {"index": 3, "path": "Video_Codec_Update.mp4.exe", "size": 350_000},     # Double extension trap
        {"index": 4, "path": "Watch_Online_Free.scr", "size": 120_000},            # ScreenSaver trap
        {"index": 5, "path": "keygen.exe", "size": 500_000}                         # Small executable in movie torrent
    ]

    res = TorrentFileInspector.inspect_file_tree(mock_files)
    assert res["context"] == "MEDIA"
    assert res["trap_count"] == 3

    files = res["files"]
    # MKV media file must be clean and checked
    assert files[0]["checked"] is True
    assert files[0]["priority"] == 4
    assert files[0]["severity"] == "CLEAN"

    # Double extension must be auto-unchecked
    assert files[3]["checked"] is False
    assert files[3]["priority"] == 0
    assert files[3]["severity"] == "CRITICAL"
    assert "double extension" in files[3]["reason"].lower()

    # .scr file must be auto-unchecked
    assert files[4]["checked"] is False
    assert files[4]["priority"] == 0
    assert files[4]["severity"] == "CRITICAL"

    # Small .exe in media torrent must be auto-unchecked
    assert files[5]["checked"] is False
    assert files[5]["priority"] == 0
    assert files[5]["severity"] == "CRITICAL"

def test_smart_inspector_game_torrent_preserves_installers():
    """
    In a game or software torrent, legitimate setup.exe and dll files
    must be FLAGGED for review (amber badge) but KEPT CHECKED by default.
    """
    mock_files = [
        {"index": 0, "path": "CyberGame/setup.exe", "size": 1_200_000_000},
        {"index": 1, "path": "CyberGame/data1.bin", "size": 4_000_000_000},
        {"index": 2, "path": "CyberGame/data2.bin", "size": 3_800_000_000},
        {"index": 3, "path": "CyberGame/Crack/steam_api64.dll", "size": 2_500_000},
        {"index": 4, "path": "CyberGame/instructions.txt", "size": 1_500}
    ]

    res = TorrentFileInspector.inspect_file_tree(mock_files)
    assert res["context"] == "SOFTWARE_OR_GAME"
    assert res["trap_count"] == 0
    assert res["review_count"] == 2  # setup.exe + steam_api64.dll

    files = res["files"]
    # setup.exe must stay checked for download with review badge
    assert files[0]["checked"] is True
    assert files[0]["priority"] == 4
    assert files[0]["severity"] == "LOW"
    assert "Review" in files[0]["badge"]

    # data1.bin must be clean
    assert files[1]["checked"] is True
    assert files[1]["severity"] == "CLEAN"

    # steam_api64.dll must stay checked
    assert files[3]["checked"] is True
    assert files[3]["severity"] == "LOW"

def test_stage3_torrent_per_file_quarantine(temp_torrent_env):
    """
    Tests Stage 3 per-file post-download security gate on completed torrent staging:
    - Quarantines CRITICAL malware/EICAR files into CyberShield vault.
    - Moves clean media & LOW warning (crack/emulator) files to final destination.
    """
    db, sm, gate, staging_dir, dest_dir = temp_torrent_env
    task_id = "test_torrent_sec"

    task_staging = sm.allocate_task_staging(task_id)

    # 1. Create a safe media file in subfolder
    sub_dir = task_staging / "MediaSubfolder"
    sub_dir.mkdir(parents=True, exist_ok=True)
    clean_file = sub_dir / "episode1.mkv"
    with open(clean_file, "wb") as f:
        f.write(b"SafeMatroskaVideoDataHeader" * 100)

    # 2. Create a game crack / emulator config (LOW warning)
    crack_file = task_staging / "steam_emu.ini"
    with open(crack_file, "w", encoding="utf-8") as f:
        f.write("[Settings]\nAppId=480\nUserName=CODEX\n")

    # 3. Create a malicious payload (EICAR standard test file)
    malicious_file = task_staging / "malicious_trap.exe"
    with open(malicious_file, "wb") as f:
        f.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    # Add task in DB
    db.add_task({
        "id": task_id,
        "url": "torrent:MockTorrent",
        "filename": "MockTorrent",
        "destination": str(dest_dir),
        "staging_path": str(task_staging),
        "engine_type": "TORRENT",
        "status": "SCANNING",
        "total_bytes": 1000,
        "num_segments": 1
    })

    worker = TorrentDownloadWorker(
        task_id=task_id,
        db=db,
        staging_manager=sm,
        security_gate=gate,
        source=None
    )

    results = worker._process_stage3_torrent(task_staging, str(dest_dir))

    assert results["status"] == "COMPLETED"
    assert results["critical_count"] == 1
    assert results["warning_count"] == 1
    assert results["clean_count"] == 1
    assert results["overall_security"] == "CRITICAL"

    # Verified clean file was moved to destination with subfolder structure preserved
    expected_clean_dest = dest_dir / "MediaSubfolder" / "episode1.mkv"
    assert expected_clean_dest.exists()

    # Game crack / warning file was moved to destination untouched
    expected_crack_dest = dest_dir / "steam_emu.ini"
    assert expected_crack_dest.exists()

    # Malicious file was quarantined and MUST NOT exist in final destination
    expected_bad_dest = dest_dir / "malicious_trap.exe"
    assert not expected_bad_dest.exists()

    # Verify task state in database
    task = db.get_task(task_id)
    assert task["security_status"] == "CRITICAL"

def test_real_libtorrent_session_lifecycle(tmp_path):
    """
    Real non-mocked libtorrent 2.1 session lifecycle test:
    Verifies add_active_torrent, pause_torrent (with save_resume_data),
    resume_torrent, and remove_torrent (with delete_files=False and True)
    all run cleanly with zero options_t / Boost.Python errors.
    """
    src_dir = tmp_path / "src_content"
    src_dir.mkdir(parents=True, exist_ok=True)
    payload_file = src_dir / "sample_iso_chunk.bin"
    payload_file.write_bytes(b"OmniFetchRealTorrentPayload" * 512)

    fl = lt.list_files(str(payload_file))
    ct = lt.create_torrent(fl)
    lt.set_piece_hashes(ct, str(src_dir))
    ti = lt.torrent_info(ct.generate())

    staging_base = tmp_path / ".staging"
    mgr = TorrentSessionManager(staging_base)

    task_id = "real_lt_lifecycle"
    task_staging = staging_base / task_id
    task_staging.mkdir(parents=True, exist_ok=True)

    # 1. Add active torrent
    handle = mgr.add_active_torrent(task_id, ti, str(task_staging), sequential=True)
    assert handle.is_valid()
    assert task_id in mgr.active_handles

    # 2. Pause torrent & persist resume.dat
    mgr.pause_torrent(task_id, str(task_staging))
    assert handle.is_valid()
    assert (task_staging / "resume.dat").exists()

    # 3. Resume torrent
    mgr.resume_torrent(task_id)
    assert handle.is_valid()

    # 4. Remove torrent keeping files (must NOT pass raw 0 / lt.options_t(0))
    mgr.remove_torrent(task_id, delete_files=False)
    assert task_id not in mgr.active_handles
    assert len(mgr.ses.get_torrents()) == 0
    deadline = time.time() + 2.0
    while handle.is_valid() and time.time() < deadline:
        time.sleep(0.02)
    assert not handle.is_valid()

    # 5. Re-add from resume.dat and remove with delete_files=True (lt.session.delete_files)
    task_id2 = "real_lt_delete"
    handle2 = mgr.add_active_torrent(task_id2, ti, str(task_staging))
    assert handle2.is_valid()
    mgr.remove_torrent(task_id2, delete_files=True)
    assert task_id2 not in mgr.active_handles
    assert len(mgr.ses.get_torrents()) == 0
    deadline = time.time() + 2.0
    while handle2.is_valid() and time.time() < deadline:
        time.sleep(0.02)
    assert not handle2.is_valid()
