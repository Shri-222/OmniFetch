"""
Sprint 2 (P1 Core Parity) Non-Mocked Integration Tests:
1. IDM-Style ETag/If-Range validation, HTTP 403 expiry -> LINK EXPIRED, Refresh Download Address
   (API + compatibility check + resume), and If-Range 200 OK mutation safety (never appends to .part).
2. Real max_concurrent_tasks FIFO queue scheduler enforcement and auto-promotion.
3. ProxyDialog/Config persistence across reload + uniform TokenBucketRateLimiter throttling in MegaDownloadWorker.
4. CyberShield read-only offline_engine.db signature matching in Stage 1 + TaskInspectorDrawer 5-tab rendering
   + Safe Brave magnet handoff routing + Scan Error badge cleanup.
"""

import asyncio
import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

import aiohttp
from aiohttp import web
from Crypto.Cipher import AES
from Crypto.Util import Counter
import pytest
from PySide6.QtWidgets import QApplication

from app.core.config import Config
from app.core.db import Database
from app.core.engine_manager import EngineManager
from app.core.security_gate import SecurityGate
from app.core.staging import StagingManager
from app.engines.http.downloader import RangeMismatchError, parse_url_expiry
from app.engines.mega.crypto import a32_to_bytes, base64_url_encode, bytes_to_a32
from app.engines.mega.client import MegaClient
from app.integrations.browser_bridge import BrowserHandoffBridge
from app.ui.download_table import DownloadTableModel
from app.ui.inspector_drawer import TaskInspectorDrawer
from app.ui.proxy_dialog import ProxyDialog


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
    cfg.max_segments_per_task = 4
    cfg.max_concurrent_tasks = 4
    cfg.minimize_to_tray = False
    cfg.notifications_enabled = False
    return cfg


def _start_bg_aiohttp_server(app: web.Application):
    port = _free_port()
    ready = threading.Event()
    state = {"loop": None, "runner": None}

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        state["loop"] = loop
        runner = web.AppRunner(app)
        state["runner"] = runner
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", port)
        loop.run_until_complete(site.start())
        ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(runner.cleanup())
            except Exception:
                pass
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    ready.wait(timeout=5)

    def stop():
        loop = state["loop"]
        if loop and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
        th.join(timeout=4)

    return port, stop


def _mega_cbc_mac(plain: bytes, aes_key: bytes, iv: bytes) -> bytes:
    chunks = []
    p = 0
    size = 131072
    while p < len(plain):
        end = min(p + size, len(plain))
        chunks.append(plain[p:end])
        p = end
        if size < 1048576:
            size += 131072

    meta_iv = iv + iv
    mac_xor = b"\x00" * 16
    for ch in chunks:
        c = AES.new(aes_key, AES.MODE_CBC, iv=meta_iv)
        padded = ch
        rem = len(padded) % 16
        if rem:
            padded = padded + b"\x00" * (16 - rem)
        enc = c.encrypt(padded)
        chunk_mac = enc[-16:]
        c_mac = AES.new(aes_key, AES.MODE_CBC, iv=mac_xor)
        mac_xor = c_mac.encrypt(chunk_mac)

    ints = bytes_to_a32(mac_xor)
    return a32_to_bytes([ints[0] ^ ints[1], ints[2] ^ ints[3]])


# ---------------------------------------------------------------------------
# TEST 1: Refresh Download Address & If-Range Mutation Safety
# ---------------------------------------------------------------------------
def test_1_refresh_download_address_and_if_range_validation(tmp_path):
    assert parse_url_expiry("https://cdn.example/f.bin?Expires=1893456000&sig=abc") == 1893456000.0
    assert parse_url_expiry("https://s3.example/f.bin?X-Amz-Date=20261126T000000Z&X-Amz-Expires=300") is not None

    payload = (b"OMNIFETCH_SPRINT2_IF_RANGE_PAYLOAD_" * 65000)[:2 * 1024 * 1024]  # 2 MB
    expected_sha = hashlib.sha256(payload).hexdigest()
    mutated_payload = (b"MUTATED_V2_RESOURCE_CONTENT_XYZ123_" * 55000)[:1600 * 1024]
    mutated_sha = hashlib.sha256(mutated_payload).hexdigest()
    wrong_payload = b"WRONG_SIZE_FILE" * 100

    state = {
        "v1_expired": False,
        "mutated": False,
        "saw_if_range": [],
    }

    def _serve_range(request, data: bytes, etag: str, filename: str, slow: bool = False):
        if request.method == "HEAD":
            return web.Response(
                headers={
                    "Content-Length": str(len(data)),
                    "Accept-Ranges": "bytes",
                    "ETag": etag,
                    "Content-Disposition": f'attachment; filename="{filename}"',
                }
            )
        rng = request.headers.get("Range", "")
        if rng.startswith("bytes="):
            s_part, e_part = rng.replace("bytes=", "").split("-")
            start = int(s_part)
            end = int(e_part) if e_part else len(data) - 1
            body = data[start:end + 1]
            return {
                "status": 206,
                "headers": {
                    "Content-Range": f"bytes {start}-{end}/{len(data)}",
                    "Content-Length": str(len(body)),
                    "Accept-Ranges": "bytes",
                    "ETag": etag,
                },
                "body": body,
                "slow": slow,
            }
        return web.Response(body=data, headers={"ETag": etag, "Accept-Ranges": "bytes"})

    async def handle_v1(request):
        if state["v1_expired"]:
            return web.Response(status=403, text="Signed URL Expired")
        res = _serve_range(request, payload, '"asset-etag-v1"', "asset_refresh.bin", slow=True)
        if isinstance(res, web.Response):
            return res
        resp = web.StreamResponse(status=res["status"], headers=res["headers"])
        await resp.prepare(request)
        pos = 0
        try:
            while pos < len(res["body"]):
                await resp.write(res["body"][pos:pos + 32768])
                pos += 32768
                await asyncio.sleep(0.025)
            await resp.write_eof()
        except Exception:
            pass
        return resp

    async def handle_v2(request):
        res = _serve_range(request, payload, '"asset-etag-v1"', "asset_refresh.bin", slow=False)
        if isinstance(res, web.Response):
            return res
        return web.Response(status=res["status"], body=res["body"], headers=res["headers"])

    async def handle_wrong(request):
        return web.Response(
            status=200 if request.method == "HEAD" else 206,
            body=b"" if request.method == "HEAD" else wrong_payload,
            headers={"Content-Length": str(len(wrong_payload)), "Accept-Ranges": "bytes", "ETag": '"wrong-etag"'},
        )

    async def handle_mutated(request):
        if request.method == "HEAD":
            data = mutated_payload if state["mutated"] else payload
            etag = '"mut-v2"' if state["mutated"] else '"mut-v1"'
            return web.Response(
                headers={
                    "Content-Length": str(len(data)),
                    "Accept-Ranges": "bytes",
                    "ETag": etag,
                    "Content-Disposition": 'attachment; filename="mutated_file.bin"',
                }
            )
        if_range = request.headers.get("If-Range")
        if if_range:
            state["saw_if_range"].append(if_range)
        if state["mutated"]:
            # If client presents stale ETag in If-Range, RFC 7233 returns full 200 OK with new ETag
            if if_range == '"mut-v1"':
                return web.Response(
                    status=200,
                    body=mutated_payload,
                    headers={"Content-Length": str(len(mutated_payload)), "Accept-Ranges": "bytes", "ETag": '"mut-v2"'},
                )
            rng = request.headers.get("Range", "")
            if rng.startswith("bytes="):
                s_part, e_part = rng.replace("bytes=", "").split("-")
                start = int(s_part)
                end = int(e_part) if e_part else len(mutated_payload) - 1
                body = mutated_payload[start:end + 1]
                return web.Response(
                    status=206,
                    body=body,
                    headers={
                        "Content-Range": f"bytes {start}-{end}/{len(mutated_payload)}",
                        "Content-Length": str(len(body)),
                        "Accept-Ranges": "bytes",
                        "ETag": '"mut-v2"',
                    },
                )
            return web.Response(status=200, body=mutated_payload, headers={"ETag": '"mut-v2"'})

        res = _serve_range(request, payload, '"mut-v1"', "mutated_file.bin", slow=True)
        resp = web.StreamResponse(status=res["status"], headers=res["headers"])
        await resp.prepare(request)
        pos = 0
        try:
            while pos < len(res["body"]):
                await resp.write(res["body"][pos:pos + 32768])
                pos += 32768
                await asyncio.sleep(0.025)
            await resp.write_eof()
        except Exception:
            pass
        return resp

    app = web.Application()
    app.router.add_route("*", "/v1/asset", handle_v1)
    app.router.add_route("*", "/v2/asset", handle_v2)
    app.router.add_route("*", "/wrong", handle_wrong)
    app.router.add_route("*", "/mutated", handle_mutated)
    port, stop_srv = _start_bg_aiohttp_server(app)

    v1_url = f"http://127.0.0.1:{port}/v1/asset?Expires=1893456000"
    v2_url = f"http://127.0.0.1:{port}/v2/asset?Expires=1893460000"
    wrong_url = f"http://127.0.0.1:{port}/wrong"
    mut_url = f"http://127.0.0.1:{port}/mutated"

    cfg = _make_cfg(tmp_path, "cfg.json", cybershield=False)
    db = Database(db_path=str(tmp_path / "sprint2_t1.db"))
    mgr = EngineManager(cfg, db)

    try:
        # ---- Part A: 403 -> LINK EXPIRED -> Refresh Download Address -> Completed ----
        tid = mgr.add_download(
            url=v1_url,
            filename="asset_refresh.bin",
            destination=cfg.download_dir,
            num_segments=4,
            custom_headers={"Referer": "https://origin.example/downloads"},
        )
        mgr.start_download(tid)

        deadline = time.time() + 10
        while time.time() < deadline:
            t = db.get_task(tid)
            if t["downloaded_bytes"] >= 900 * 1024:
                break
            time.sleep(0.05)

        mgr.pause_download(tid)
        t_paused = db.get_task(tid)
        assert t_paused["status"] == "PAUSED"
        assert t_paused["etag"] == '"asset-etag-v1"'
        assert t_paused["origin_referer"] == "https://origin.example/downloads"
        assert t_paused["expires_at"] == 1893456000.0

        part_files_before = sorted(Path(t_paused["staging_path"]).glob("segment_*.part"))
        assert len(part_files_before) >= 1
        sizes_before = {p.name: p.stat().st_size for p in part_files_before}

        # Switch v1 to return HTTP 403 and resume -> must transition to LINK EXPIRED preserving .part
        state["v1_expired"] = True
        mgr.resume_download(tid)
        deadline = time.time() + 10
        while time.time() < deadline:
            t_exp = db.get_task(tid)
            if t_exp["status"] == "LINK EXPIRED":
                break
            time.sleep(0.05)

        t_exp = db.get_task(tid)
        assert t_exp["status"] == "LINK EXPIRED"
        assert t_exp["speed_bps"] == 0.0
        assert t_exp["eta_seconds"] == 0
        for name, sz in sizes_before.items():
            assert (Path(t_exp["staging_path"]) / name).stat().st_size == sz

        # Reject incompatible Content-Length URL cleanly
        bad_refresh = mgr.refresh_download_address(tid, wrong_url)
        assert bad_refresh["success"] is False
        assert bad_refresh["compatible"] is False
        assert "mismatch" in bad_refresh["reason"].lower()

        # Refresh with compatible v2 URL and resume cleanly to 100%
        ok_refresh = mgr.refresh_download_address(tid, v2_url, custom_headers={"Referer": "https://origin.example/v2"})
        assert ok_refresh["success"] is True
        t_refreshed = db.get_task(tid)
        assert t_refreshed["url"] == v2_url
        assert t_refreshed["status"] == "PAUSED"
        assert t_refreshed["expires_at"] == 1893460000.0

        mgr.resume_download(tid)
        deadline = time.time() + 15
        while time.time() < deadline:
            t_done = db.get_task(tid)
            if t_done["status"] == "COMPLETED":
                break
            time.sleep(0.05)

        t_done = db.get_task(tid)
        assert t_done["status"] == "COMPLETED", f"Refreshed download failed: {t_done}"
        out_path = Path(cfg.download_dir) / "asset_refresh.bin"
        assert hashlib.sha256(out_path.read_bytes()).hexdigest() == expected_sha

        # ---- Part B: If-Range returning 200 OK on mutated file NEVER appends onto .part ----
        tid_mut = mgr.add_download(url=mut_url, filename="mutated_file.bin", destination=cfg.download_dir, num_segments=4)
        mgr.start_download(tid_mut)
        deadline = time.time() + 10
        while time.time() < deadline:
            tm = db.get_task(tid_mut)
            if tm["downloaded_bytes"] >= 700 * 1024:
                break
            time.sleep(0.05)

        mgr.pause_download(tid_mut)
        tm = db.get_task(tid_mut)
        segs_mut = db.get_segments(tid_mut)
        p0_path = Path(tm["staging_path"]) / "segment_0.part"
        assert p0_path.exists()
        p0_size_before = p0_path.stat().st_size

        # Mutate remote asset & verify _download_segment raises RangeMismatchError WITHOUT appending to part_0
        state["mutated"] = True

        async def _check_seg_guard():
            async with aiohttp.ClientSession() as sess:
                seg0 = dict(segs_mut[0])
                seg0["retries"] = 0
                with pytest.raises(RangeMismatchError):
                    await mgr.http_downloader._download_segment(sess, tid_mut, seg0)

        asyncio.run(_check_seg_guard())
        assert p0_path.stat().st_size == p0_size_before, "_download_segment must NEVER append on HTTP 200!"
        assert '"mut-v1"' in state["saw_if_range"]

        # Full task resume cleanly wipes stale parts and downloads mutated v2 cleanly
        mgr.resume_download(tid_mut)
        deadline = time.time() + 15
        while time.time() < deadline:
            tm2 = db.get_task(tid_mut)
            if tm2["status"] == "COMPLETED":
                break
            time.sleep(0.05)

        tm2 = db.get_task(tid_mut)
        assert tm2["status"] == "COMPLETED", f"Mutated restart failed: {tm2}"
        out_mut = Path(cfg.download_dir) / "mutated_file.bin"
        assert len(out_mut.read_bytes()) == len(mutated_payload)
        assert hashlib.sha256(out_mut.read_bytes()).hexdigest() == mutated_sha
    finally:
        stop_srv()
        mgr.shutdown()


# ---------------------------------------------------------------------------
# TEST 2: Real Concurrency Queue Enforcement (max_concurrent_tasks = 2)
# ---------------------------------------------------------------------------
def test_2_concurrency_queue_scheduler_fifo_enforcement(tmp_path):
    file_payload = (b"QUEUE_TEST_PAYLOAD_0123456789_" * 20000)[:512 * 1024]  # 512 KB
    expected_sha = hashlib.sha256(file_payload).hexdigest()

    async def handle_qfile(request):
        if request.method == "HEAD":
            return web.Response(headers={"Content-Length": str(len(file_payload)), "Accept-Ranges": "bytes"})
        resp = web.StreamResponse(status=200, headers={"Content-Length": str(len(file_payload))})
        await resp.prepare(request)
        for pos in range(0, len(file_payload), 65536):
            await resp.write(file_payload[pos:pos + 65536])
            await asyncio.sleep(0.04)
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route("*", "/{fname}", handle_qfile)
    port, stop_srv = _start_bg_aiohttp_server(app)

    cfg = _make_cfg(tmp_path, "cfg_q.json", cybershield=False)
    cfg.max_concurrent_tasks = 2
    cfg.max_segments_per_task = 1
    db = Database(db_path=str(tmp_path / "queue.db"))
    mgr = EngineManager(cfg, db)

    try:
        tids = [
            mgr.add_download(f"http://127.0.0.1:{port}/q{i}.bin", filename=f"q{i}.bin", destination=cfg.download_dir)
            for i in range(4)
        ]
        for tid in tids:
            mgr.start_download(tid)

        # Immediately after queuing 4 tasks with cap=2, at most 2 workers can be active and tail tasks remain QUEUED
        with mgr._queue_lock:
            initial_active = len(mgr.active_workers)
            initial_queued = len(mgr._pending_queue)
        assert initial_active <= 2
        assert initial_queued >= 2

        peak_workers = initial_active
        deadline = time.time() + 15
        while time.time() < deadline:
            with mgr._queue_lock:
                peak_workers = max(peak_workers, len(mgr.active_workers))
            rows = [db.get_task(tid) for tid in tids]
            if all(r["status"] == "COMPLETED" for r in rows):
                break
            time.sleep(0.03)

        assert peak_workers <= 2, f"Concurrency cap violated: peak active_workers={peak_workers}"
        for i, tid in enumerate(tids):
            row = db.get_task(tid)
            assert row["status"] == "COMPLETED", f"Queued task {tid} did not auto-promote/complete: {row}"
            assert hashlib.sha256((Path(cfg.download_dir) / f"q{i}.bin").read_bytes()).hexdigest() == expected_sha
    finally:
        stop_srv()
        mgr.shutdown()


# ---------------------------------------------------------------------------
# TEST 3: MEGA Global Speed Cap + Proxy Persistence
# ---------------------------------------------------------------------------
def test_3_mega_rate_limiter_and_proxy_persistence(tmp_path, qt_app, monkeypatch):
    # Part A: ProxyDialog -> Config persistence -> fresh EngineManager reload
    cfg_path = tmp_path / "proxy_cfg.json"
    cfg1 = _make_cfg(tmp_path, "proxy_cfg.json", cybershield=False)
    db1 = Database(db_path=str(tmp_path / "p1.db"))
    mgr1 = EngineManager(cfg1, db1)

    dlg = ProxyDialog(mgr1.proxy_pool, config=cfg1)
    dlg.passive_chk.setChecked(False)
    dlg.proxy_edit.setPlainText("127.0.0.1:8888\nhttp://user:pass@10.0.0.2:3128")
    dlg._save_and_apply()
    mgr1.shutdown()

    cfg2 = Config(config_path=cfg_path)
    assert cfg2.proxy_passive_mode is False
    assert cfg2.proxies == ["127.0.0.1:8888", "http://user:pass@10.0.0.2:3128"]
    db2 = Database(db_path=str(tmp_path / "p2.db"))
    mgr2 = EngineManager(cfg2, db2)
    assert mgr2.proxy_pool.passive_mode is False
    assert [e.raw for e in mgr2.proxy_pool.entries] == ["127.0.0.1:8888", "http://user:pass@10.0.0.2:3128"]
    mgr2.shutdown()

    # Part B: TokenBucketRateLimiter throttling MegaDownloadWorker uniformly
    raw_k = os.urandom(32)
    k_ints = bytes_to_a32(raw_k)
    aes_key = a32_to_bytes([k_ints[0] ^ k_ints[2], k_ints[1] ^ k_ints[3], k_ints[4] ^ k_ints[6], k_ints[5] ^ k_ints[7]])
    iv = raw_k[16:24]
    plain = (b"MEGA_THROTTLE_TEST_PAYLOAD_01234" * 16000)[:384 * 1024]  # 384 KB
    meta_mac = _mega_cbc_mac(plain, aes_key, iv)
    full_key_bytes = raw_k[:24] + meta_mac
    mega_key_b64 = base64_url_encode(full_key_bytes)
    encrypted = AES.new(aes_key, AES.MODE_CTR, counter=Counter.new(64, prefix=iv, initial_value=0)).encrypt(plain)

    async def handle_mega_dl(request):
        rng = request.headers.get("Range", "bytes=0-")
        start = int(rng.replace("bytes=", "").split("-")[0])
        end = len(encrypted) - 1
        body = encrypted[start:end + 1]
        return web.Response(
            status=206,
            body=body,
            headers={
                "Content-Range": f"bytes {start}-{end}/{len(encrypted)}",
                "Content-Length": str(len(body)),
            },
        )

    app = web.Application()
    app.router.add_get("/mega_throttled", handle_mega_dl)
    port, stop_srv = _start_bg_aiohttp_server(app)

    async def fake_get_file_info(self, file_id, file_key):
        return {
            "id": file_id,
            "filename": "throttled_mega.bin",
            "size": len(plain),
            "aes_key": aes_key,
            "iv": iv,
            "meta_mac": meta_mac,
            "download_url": f"http://127.0.0.1:{port}/mega_throttled",
        }

    monkeypatch.setattr(MegaClient, "get_file_info", fake_get_file_info)

    cfg3 = _make_cfg(tmp_path, "cfg_mega_cap.json", cybershield=False)
    cfg3.speed_limit_kbs = 128  # 128 KB/s cap
    db3 = Database(db_path=str(tmp_path / "mega_cap.db"))
    mgr3 = EngineManager(cfg3, db3)

    try:
        t0 = time.time()
        tid = mgr3.add_mega_download(f"https://mega.nz/file/TestCap1#{mega_key_b64}", filename="throttled_mega.bin")
        deadline = time.time() + 15
        while time.time() < deadline:
            row = db3.get_task(tid)
            if row["status"] == "COMPLETED":
                break
            time.sleep(0.05)
        elapsed = time.time() - t0

        row = db3.get_task(tid)
        assert row["status"] == "COMPLETED"
        out_mega = Path(cfg3.download_dir) / "throttled_mega.bin"
        assert hashlib.sha256(out_mega.read_bytes()).hexdigest() == hashlib.sha256(plain).hexdigest()
        # First 128 KB bucket is instant; remaining 256 KB at 128 KB/s must take ~2.0s (>= 1.4s safety margin)
        assert elapsed >= 1.4, f"MEGA download completed too fast ({elapsed:.2f}s) for 128 KB/s cap!"
    finally:
        stop_srv()
        mgr3.shutdown()


# ---------------------------------------------------------------------------
# TEST 4: Stage 1 Read-Only Threat DB Check + Inspector Drawer + Magnet Parity
# ---------------------------------------------------------------------------
def test_4_stage1_readonly_db_and_inspector_drawer_and_bridge(tmp_path, qt_app):
    cybershield_db = Path(r"C:\Users\shrey\Desktop\CyberShield\data\offline_engine.db")
    mtime_before = cybershield_db.stat().st_mtime

    cfg = _make_cfg(tmp_path, "cfg_sec.json", cybershield=True)
    db = Database(db_path=str(tmp_path / "sec_insp.db"))
    mgr = EngineManager(cfg, db)
    sm = StagingManager(cfg.staging_dir)
    gate = SecurityGate(db=db, staging_manager=sm)

    try:
        # 1. Stage 1 read-only offline_engine.db signature queries
        res_crit_regex = gate.evaluate_pre_download("https://bad.example/invoice.pdf.exe", "invoice.pdf.exe")
        assert res_crit_regex["allowed"] is False
        assert res_crit_regex["verdict"] == "BLOCK_CRITICAL"
        assert res_crit_regex["signature_id"] == "THREAT-CRIT-008"

        res_crit_token = gate.evaluate_pre_download("https://bad.example/drops/PavinLoader_dropper.bin", "PavinLoader_dropper.bin")
        assert res_crit_token["allowed"] is False
        assert res_crit_token["verdict"] == "BLOCK_CRITICAL"
        assert res_crit_token["signature_id"] in ("THREAT-CRIT-001", "THREAT-CRIT-002")

        res_warn = gate.evaluate_pre_download("https://files.example/crack.zip", "crack.zip")
        assert res_warn["allowed"] is True
        assert res_warn["verdict"] == "ALLOW_WARNING"
        assert res_warn["signature_id"] == "THREAT-LOW-005"

        assert cybershield_db.stat().st_mtime == mtime_before, "CyberShield offline_engine.db was modified!"

        # 2. TaskInspectorDrawer 5-tab rendering + Scan Error badge emoji cleanup
        tid = "insp0001"
        staged_dir = sm.allocate_task_staging(tid)
        db.add_task({
            "id": tid,
            "url": "https://cdn.example/installer.zip?Expires=1893456000",
            "filename": "installer.zip",
            "destination": cfg.download_dir,
            "staging_path": str(staged_dir),
            "engine_type": "HTTP",
            "status": "PAUSED",
            "total_bytes": 1024000,
            "downloaded_bytes": 512000,
            "num_segments": 2,
            "resumable": 1,
            "etag": '"insp-etag-1"',
            "expires_at": time.time() + 1200,
            "error_message": "Simulated connection drop",
        })
        db.save_segments(tid, [
            {"index": 0, "start": 0, "end": 511999, "current": 512000, "status": "COMPLETED"},
            {"index": 1, "start": 512000, "end": 1023999, "current": 512000, "status": "PENDING"},
        ])
        db.record_security_audit(tid, "PRE_DOWNLOAD", "ALLOW_CLEAN", None, "Clean URL check")

        drawer = TaskInspectorDrawer()
        task_row = db.get_task(tid)
        drawer.update_for_task(task_row, mgr)
        for tab_i in range(drawer.tabs.count()):
            drawer.tabs.setCurrentIndex(tab_i)
            qt_app.processEvents()

        assert '"insp-etag-1"' in drawer.lbl_gen_validator.text()
        assert "Valid (" in drawer.lbl_gen_expiry.text()
        assert "Simulated connection drop" in drawer.txt_gen_error.toPlainText()
        assert drawer.segments_table.rowCount() == 2
        assert drawer.files_table.rowCount() == 1
        assert drawer.security_table.rowCount() == 1

        # Verify Scan Error badge has no leftover emoji
        scan_err_row = dict(task_row, status="FAILED", threat_details="SCAN_ERROR: timeout")
        mdl = DownloadTableModel([scan_err_row])
        assert mdl.data(mdl.index(0, 8)) == "Scan Error"

        # 3. Magnet handoff routes through inspection signal when magnet_inspector_enabled=True
        cfg.brave_handoff_port = _free_port()
        cfg.brave_handoff_token = "tok_s2_mag"
        bridge = BrowserHandoffBridge(cfg, mgr)
        bridge.magnet_inspector_enabled = True
        captured_magnets = []
        bridge.magnet_handoff_requested.connect(lambda u, fn: captured_magnets.append((u, fn)))
        assert bridge.start()
        time.sleep(0.15)
        try:
            magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=SampleISO"
            req = urllib.request.Request(
                f"http://127.0.0.1:{cfg.brave_handoff_port}/api/handoff",
                data=json.dumps({"url": magnet, "filename": "SampleISO"}).encode(),
                headers={"X-OmniFetch-Token": cfg.brave_handoff_token, "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode())
                assert body["mode"] == "magnet_inspection"
                assert body["task_id"] is None

            for _ in range(20):
                qt_app.processEvents()
                if captured_magnets:
                    break
                time.sleep(0.05)
            assert len(captured_magnets) == 1
            assert captured_magnets[0][0] == magnet
        finally:
            bridge.stop()

        # Verify background.js checks handoffOk BEFORE cancelling chrome.downloads
        bg_src = Path(r"C:\Users\shrey\Desktop\OmniFetch\browser_extension\background.js").read_text(encoding="utf-8")
        assert bg_src.index("await handoffLink(") < bg_src.index("chrome.downloads.cancel(")
    finally:
        mgr.shutdown()
