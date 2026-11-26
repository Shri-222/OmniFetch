"""
Tests for Staging Containment Engine and CyberShield 3-Stage Security Gate
"""

import os
import shutil
import tempfile
import pytest
from pathlib import Path

from app.core.staging import StagingManager
from app.core.security_gate import SecurityGate
from app.core.db import Database
from app.integrations.cybershield_bridge import CyberShieldBridge

@pytest.fixture
def temp_dirs():
    tmp_base = tempfile.mkdtemp(prefix="omnifetch_test_")
    staging_dir = Path(tmp_base) / ".staging"
    dest_dir = Path(tmp_base) / "downloads"
    yield staging_dir, dest_dir
    shutil.rmtree(tmp_base, ignore_errors=True)

@pytest.fixture
def memory_db():
    db = Database(":memory:")
    yield db
    db.close()

def test_staging_assembly_and_move(temp_dirs):
    staging_dir, dest_dir = temp_dirs
    sm = StagingManager(staging_dir)
    task_id = "test_task_123"

    # Write 3 mock segments
    seg0 = sm.get_segment_path(task_id, 0)
    seg1 = sm.get_segment_path(task_id, 1)
    seg2 = sm.get_segment_path(task_id, 2)

    with open(seg0, "wb") as f:
        f.write(b"CHUNK_ZERO_")
    with open(seg1, "wb") as f:
        f.write(b"CHUNK_ONE_")
    with open(seg2, "wb") as f:
        f.write(b"CHUNK_TWO")

    # Assemble
    staged_file = sm.assemble_segments(task_id, "combined.bin", 3)
    assert os.path.exists(staged_file)

    # Check content
    with open(staged_file, "rb") as f:
        data = f.read()
    assert data == b"CHUNK_ZERO_CHUNK_ONE_CHUNK_TWO"

    # Verify temp parts were cleaned up
    assert not seg0.exists()
    assert not seg1.exists()
    assert not seg2.exists()

    # Move to destination
    final_path = sm.move_to_destination(staged_file, dest_dir)
    assert os.path.exists(final_path)
    assert Path(final_path).name == "combined.bin"

    # Test collision handling: move another file with same name
    staged_copy = sm.get_staged_file_path(task_id, "combined.bin")
    with open(staged_copy, "wb") as f:
        f.write(b"SECOND_FILE")
    second_final = sm.move_to_destination(staged_copy, dest_dir)
    assert os.path.exists(second_final)
    assert Path(second_final).name == "combined (1).bin"

def test_security_gate_stage1_pre_download():
    gate = SecurityGate()

    # Clean document
    clean_eval = gate.evaluate_pre_download("https://example.com/report.pdf", "report.pdf")
    assert clean_eval["allowed"] is True
    assert clean_eval["verdict"] == "ALLOW_CLEAN"

    # Masqueraded double extension (trap)
    trap_eval = gate.evaluate_pre_download("https://malicious.com/invoice.pdf.exe", "invoice.pdf.exe")
    assert trap_eval["allowed"] is False
    assert trap_eval["verdict"] == "BLOCK_CRITICAL"
    assert trap_eval["threat_name"] == "Exploit.DoubleExtension"

    # Standalone executable (warning only)
    exe_eval = gate.evaluate_pre_download("https://example.com/installer.exe", "installer.exe")
    assert exe_eval["allowed"] is True
    assert exe_eval["verdict"] == "ALLOW_WARNING"

def test_security_gate_stage3_clean_file(temp_dirs, memory_db):
    staging_dir, dest_dir = temp_dirs
    sm = StagingManager(staging_dir)
    gate = SecurityGate(db=memory_db, staging_manager=sm)

    task_id = "clean_task"
    staged_file = sm.get_staged_file_path(task_id, "safe_doc.txt")
    with open(staged_file, "w", encoding="utf-8") as f:
        f.write("Safe and clean document text.")

    res = gate.evaluate_post_download(task_id, staged_file, dest_dir)
    assert res["action"] == "MOVED_CLEAN"
    assert res["verdict"] == "ALLOW_CLEAN"
    assert os.path.exists(res["final_path"])

def test_security_gate_stage3_critical_eicar_quarantine(temp_dirs, memory_db):
    staging_dir, dest_dir = temp_dirs
    sm = StagingManager(staging_dir)
    gate = SecurityGate(db=memory_db, staging_manager=sm)

    task_id = "critical_task"
    staged_file = sm.get_staged_file_path(task_id, "test_eicar.com")
    # Standard EICAR Antivirus Test string
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(staged_file, "wb") as f:
        f.write(eicar_bytes)

    res = gate.evaluate_post_download(task_id, staged_file, dest_dir)
    # Must be intercepted by CyberShield heuristics / Defender pass
    assert res["action"] == "QUARANTINED"
    assert res["verdict"] == "BLOCK_CRITICAL"
    assert res["severity"] == "CRITICAL"
    # The file must NOT be moved into user downloads
    assert not (Path(dest_dir) / "test_eicar.com").exists()

def test_security_gate_stage3_low_crack_warning(temp_dirs, memory_db):
    staging_dir, dest_dir = temp_dirs
    sm = StagingManager(staging_dir)
    gate = SecurityGate(db=memory_db, staging_manager=sm)

    task_id = "crack_warning_task"
    staged_file = sm.get_staged_file_path(task_id, "steam_emu.ini")
    with open(staged_file, "w", encoding="utf-8") as f:
        f.write("[Settings]\nAppId=480\nUserName=CODEX\nLanguage=english\n")

    res = gate.evaluate_post_download(task_id, staged_file, dest_dir)
    # Game crack / emulator must be ALLOW_WARNING, never quarantined
    assert res["action"] == "MOVED_WARNING"
    assert res["verdict"] == "ALLOW_WARNING"
    assert res["severity"] == "LOW"
    assert (Path(dest_dir) / "steam_emu.ini").exists()

def test_cybershield_bridge_readonly_query():
    bridge = CyberShieldBridge()
    sigs = bridge.query_threat_signatures_readonly()
    # Must retrieve signatures from offline_engine.db without throwing
    assert isinstance(sigs, list)
    if sigs:
        assert "name" in sigs[0]
        assert "severity" in sigs[0]
