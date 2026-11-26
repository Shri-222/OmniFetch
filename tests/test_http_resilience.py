"""
OmniFetch HTTP Engine Resilience & Diagnostic Regression Test Suite
Verifies:
1. HEAD returning 405/403 falls back to GET Range 0-0 and downloads successfully.
2. Unknown Content-Length (Transfer-Encoding: chunked / 0 total bytes) downloads cleanly via single stream fallback.
3. Real filename resolution: RFC 5987 filename*=, filename=, URL basename, and MIME extension derivation (.png, .xlsx), plus blob:/data: rejection.
4. Error handling: HTTP 404 or connection failures immediately transition task to FAILED with descriptive error_message in SQLite.
5. Browser bridge handoff passes Cookie, Referer, and User-Agent headers to the download pipeline.
"""

import os
import shutil
import hashlib
import tempfile
import asyncio
import threading
import json
import pytest
from pathlib import Path
from aiohttp import web
import aiohttp

from app.core.config import Config
from app.core.db import Database
from app.core.staging import StagingManager
from app.core.engine_manager import EngineManager
from app.engines.http.downloader import HttpDownloader
from app.integrations.browser_bridge import BrowserHandoffBridge

RESILIENCE_PAYLOAD = b"OmniFetchResilienceChunkPayloadData" * 1024  # ~35 KB

@pytest.fixture
def resilience_env():
    tmp = tempfile.mkdtemp(prefix="omnifetch_resilience_")
    db_path = Path(tmp) / "resilience.db"
    staging_dir = Path(tmp) / ".staging"
    dest_dir = Path(tmp) / "downloads"
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    db = Database(str(db_path))
    sm = StagingManager(staging_dir)
    cfg = Config()
    cfg.download_dir = str(dest_dir)
    cfg.brave_handoff_token = "test_resilience_token"
    
    yield db, sm, dest_dir, cfg
    
    db.close()
    shutil.rmtree(tmp, ignore_errors=True)

@pytest.fixture(scope="module")
def resilience_server():
    """
    Spins up a multi-endpoint test HTTP server on an ephemeral port.
    Endpoints:
    - /head-reject: Returns 405 on HEAD; supports GET Range and full GET.
    - /chunked: Returns chunked response without Content-Length.
    - /headers-check: Inspects forwarded Cookie, Referer, User-Agent.
    - /not-found: Returns 404.
    """
    loop = asyncio.new_event_loop()
    server_info = {}

    async def handle_head_reject(request):
        if request.method == "HEAD":
            return web.Response(status=405, text="Method Not Allowed")
        
        range_header = request.headers.get("Range")
        if range_header and range_header.startswith("bytes="):
            byte_range = range_header.replace("bytes=", "")
            parts = byte_range.split("-")
            start = int(parts[0])
            end = int(parts[1]) if parts[1] else len(RESILIENCE_PAYLOAD) - 1
            chunk = RESILIENCE_PAYLOAD[start:end + 1]
            return web.Response(
                body=chunk,
                status=206,
                headers={
                    "Content-Range": f"bytes {start}-{end}/{len(RESILIENCE_PAYLOAD)}",
                    "Content-Length": str(len(chunk)),
                    "Accept-Ranges": "bytes",
                    "Content-Disposition": 'attachment; filename="head_rejected_sample.dat"'
                }
            )
        return web.Response(
            body=RESILIENCE_PAYLOAD,
            status=200,
            headers={
                "Content-Length": str(len(RESILIENCE_PAYLOAD)),
                "Accept-Ranges": "bytes",
                "Content-Disposition": 'attachment; filename="head_rejected_sample.dat"'
            }
        )

    async def handle_chunked(request):
        # Stream chunks without Content-Length
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="streamed_chunked.bin"'
            }
        )
        await response.prepare(request)
        for i in range(0, len(RESILIENCE_PAYLOAD), 4096):
            await response.write(RESILIENCE_PAYLOAD[i:i + 4096])
        await response.write_eof()
        return response

    async def handle_headers_check(request):
        cookie = request.headers.get("Cookie", "")
        referer = request.headers.get("Referer", "")
        ua = request.headers.get("User-Agent", "")
        
        # Verify custom headers passed
        if "test_auth_cookie=12345" in cookie and "https://drive.google.com" in referer:
            return web.Response(
                body=b"AUTHENTICATED_OK",
                status=200,
                headers={
                    "Content-Length": str(len(b"AUTHENTICATED_OK")),
                    "Content-Disposition": 'attachment; filename="google_auth_export.xlsx"'
                }
            )
        else:
            return web.Response(body=b"MISSING_HEADERS", status=403)

    async def handle_not_found(request):
        return web.Response(status=404, text="Item not found")

    drop_state = {"calls": 0}

    async def handle_drop_midstream(request):
        drop_state["calls"] += 1
        call_num = drop_state["calls"]
        total_len = len(RESILIENCE_PAYLOAD)
        range_header = request.headers.get("Range")

        if request.method == "HEAD":
            return web.Response(
                status=200,
                headers={
                    "Content-Length": str(total_len),
                    "Accept-Ranges": "bytes",
                    "Content-Disposition": 'attachment; filename="recovered_stream.bin"'
                }
            )

        start = 0
        end = total_len - 1
        status = 200
        if range_header and range_header.startswith("bytes="):
            parts = range_header.replace("bytes=", "").split("-")
            start = int(parts[0])
            end = int(parts[1]) if parts[1] else total_len - 1
            status = 206

        slice_data = RESILIENCE_PAYLOAD[start:end + 1]
        headers = {
            "Content-Length": str(len(slice_data)),
            "Accept-Ranges": "bytes",
            "Content-Disposition": 'attachment; filename="recovered_stream.bin"'
        }
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end}/{total_len}"

        resp = web.StreamResponse(status=status, headers=headers)
        await resp.prepare(request)

        # Intentionally sever the TCP connection halfway on the first full-stream body attempt
        if start == 0 and end > 100 and call_num <= 2:
            half = len(slice_data) // 3
            await resp.write(slice_data[:half])
            await asyncio.sleep(0.05)
            request.transport.close()
            return resp

        await resp.write(slice_data)
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route("*", "/head-reject", handle_head_reject)
    app.router.add_route("*", "/chunked", handle_chunked)
    app.router.add_route("*", "/headers-check", handle_headers_check)
    app.router.add_route("*", "/not-found", handle_not_found)
    app.router.add_route("*", "/drop-midstream", handle_drop_midstream)

    runner = web.AppRunner(app)

    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port = site._server.sockets[0].getsockname()[1]
        server_info["base_url"] = f"http://127.0.0.1:{port}"
        server_info["ready"] = True
        loop.run_forever()

    t = threading.Thread(target=run_loop, daemon=True)
    t.start()

    while "ready" not in server_info:
        import time
        time.sleep(0.05)

    yield server_info["base_url"]

    loop.call_soon_threadsafe(loop.stop)


@pytest.mark.asyncio
async def test_head_reject_get_fallback_download(resilience_server, resilience_env):
    """
    Test 1: Server rejects HEAD with 405. Probe must automatically fall back
    to GET Range: bytes=0-0 and successfully perform download.
    """
    db, sm, dest_dir, cfg = resilience_env
    downloader = HttpDownloader(db, sm)
    url = f"{resilience_server}/head-reject"
    
    probe_res = await downloader.probe(url)
    assert probe_res["status"] == 206
    assert probe_res["total_bytes"] == len(RESILIENCE_PAYLOAD)
    assert probe_res["accept_ranges"] is True
    assert probe_res["filename"] == "head_rejected_sample.dat"

    task_id = "test_head_fallback"
    staging_path = sm.allocate_task_staging(task_id)
    db.add_task({
        "id": task_id,
        "url": url,
        "filename": "download.bin",
        "destination": str(dest_dir),
        "staging_path": str(staging_path),
        "engine_type": "HTTP",
        "status": "QUEUED",
        "total_bytes": 0,
        "num_segments": 2
    })

    res = await downloader.download_task(task_id)
    assert res.get("status") == "COMPLETED" or "final_path" in res

    task = db.get_task(task_id)
    assert task["status"] == "COMPLETED"
    assert task["filename"] == "head_rejected_sample.dat"
    assert task["downloaded_bytes"] == len(RESILIENCE_PAYLOAD)

    dest_file = dest_dir / "head_rejected_sample.dat"
    assert dest_file.exists()
    assert dest_file.stat().st_size == len(RESILIENCE_PAYLOAD)
    with open(dest_file, "rb") as f:
        assert f.read() == RESILIENCE_PAYLOAD


@pytest.mark.asyncio
async def test_chunked_unknown_size_single_stream_fallback(resilience_server, resilience_env):
    """
    Test 2: Server returns chunked stream with unknown Content-Length (total_bytes=0).
    Downloader must dynamically route to single-stream fallback, write to staging,
    update progress, finalize at EOF, and mark task COMPLETED (never stuck in DOWNLOADING).
    """
    db, sm, dest_dir, cfg = resilience_env
    downloader = HttpDownloader(db, sm)
    url = f"{resilience_server}/chunked"

    task_id = "test_chunked_stream"
    staging_path = sm.allocate_task_staging(task_id)
    db.add_task({
        "id": task_id,
        "url": url,
        "filename": "download.bin",
        "destination": str(dest_dir),
        "staging_path": str(staging_path),
        "engine_type": "HTTP",
        "status": "QUEUED",
        "total_bytes": 0,
        "num_segments": 4
    })

    progress_updates = []
    def on_progress(p):
        progress_updates.append(p)

    res = await downloader.download_task(task_id, progress_callback=on_progress)
    assert res.get("status") == "COMPLETED" or "final_path" in res

    task = db.get_task(task_id)
    assert task["status"] == "COMPLETED"
    assert task["filename"] == "streamed_chunked.bin"
    assert task["downloaded_bytes"] == len(RESILIENCE_PAYLOAD)
    assert task["total_bytes"] == len(RESILIENCE_PAYLOAD)

    dest_file = dest_dir / "streamed_chunked.bin"
    assert dest_file.exists()
    assert dest_file.stat().st_size == len(RESILIENCE_PAYLOAD)
    with open(dest_file, "rb") as f:
        assert f.read() == RESILIENCE_PAYLOAD


def test_real_filename_resolution_priorities(resilience_env):
    """
    Test 3: Filename resolution in priority order:
    1. Caller filename (if non-generic)
    2. RFC 5987 filename*= UTF-8
    3. Standard filename=
    4. URL basename
    5. MIME fallback extension (.webp, .png, .xlsx)
    6. Rejection of blob: and data: URLs
    """
    db, sm, dest_dir, cfg = resilience_env
    dl = HttpDownloader(db, sm)

    # 1. Caller filename has top priority
    fn1 = dl._resolve_filename(
        url="https://example.com/files/export?id=99",
        disposition='attachment; filename="disposition_name.bin"',
        caller_filename="explicit_user_choice.zip"
    )
    assert fn1 == "explicit_user_choice.zip"

    # 2. RFC 5987 filename*=UTF-8''
    fn2 = dl._resolve_filename(
        url="https://example.com/download/doc",
        disposition="attachment; filename*=UTF-8''Project%20Budget%20%28Q4%29.pdf"
    )
    assert fn2 == "Project Budget (Q4).pdf"

    # 3. Standard Content-Disposition
    fn3 = dl._resolve_filename(
        url="https://example.com/data/query",
        disposition='attachment; filename="financial_records.xlsx"'
    )
    assert fn3 == "financial_records.xlsx"

    # 4. URL path basename
    fn4 = dl._resolve_filename(
        url="https://example.com/images/gallery/mountain_landscape.webp?width=1920&token=xyz"
    )
    assert fn4 == "mountain_landscape.webp"

    # 5. MIME fallback when basename lacks recognizable extension
    fn5_img = dl._resolve_filename(
        url="https://example.com/api/v1/avatar/view",
        content_type="image/png"
    )
    assert fn5_img == "view.png"

    fn5_excel = dl._resolve_filename(
        url="https://docs.google.com/spreadsheets/d/12345/export",
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    assert fn5_excel == "export.xlsx"


@pytest.mark.asyncio
async def test_blob_and_data_urls_clean_rejection(resilience_env):
    """
    Test 3b: Verifies blob: and data: URLs are rejected cleanly without hanging.
    """
    db, sm, dest_dir, cfg = resilience_env
    dl = HttpDownloader(db, sm)

    res_blob = await dl.probe("blob:http://localhost:8080/4f2b96e0-1c93-4a11")
    assert "error" in res_blob
    assert "blob:" in res_blob["error"]

    res_data = await dl.probe("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...")
    assert "error" in res_data
    assert "data:" in res_data["error"]


@pytest.mark.asyncio
async def test_failed_404_transitions_to_failed_status(resilience_server, resilience_env):
    """
    Test 4: HTTP 404 or network failure immediately transitions task status to FAILED
    with a non-empty human-readable error_message in SQLite (never stuck in DOWNLOADING).
    """
    db, sm, dest_dir, cfg = resilience_env
    downloader = HttpDownloader(db, sm)
    url = f"{resilience_server}/not-found"

    task_id = "test_404_failure"
    staging_path = sm.allocate_task_staging(task_id)
    db.add_task({
        "id": task_id,
        "url": url,
        "filename": "download.bin",
        "destination": str(dest_dir),
        "staging_path": str(staging_path),
        "engine_type": "HTTP",
        "status": "QUEUED",
        "total_bytes": 0,
        "num_segments": 1
    })

    with pytest.raises(Exception):
        await downloader.download_task(task_id)

    task = db.get_task(task_id)
    assert task["status"] == "FAILED"
    assert task["error_message"] is not None
    assert "404" in task["error_message"] or "Not Found" in task["error_message"]


@pytest.mark.asyncio
async def test_browser_bridge_header_forwarding(resilience_server, resilience_env):
    """
    Test 5: Browser bridge forwards Cookie, Referer, and User-Agent headers,
    enabling authenticated endpoints (e.g. Google Drive/Docs) to download successfully.
    """
    db, sm, dest_dir, cfg = resilience_env
    em = EngineManager(config=cfg, db=db)
    bridge = BrowserHandoffBridge(cfg, em)

    target_url = f"{resilience_server}/headers-check"
    custom_headers = {
        "Cookie": "test_auth_cookie=12345; session=active",
        "Referer": "https://drive.google.com/drive/u/0/folders/abc",
        "User-Agent": "Mozilla/5.0 Brave/OmniFetchTest"
    }

    # Add task with forwarded custom headers
    task_id = em.add_download(
        url=target_url,
        filename="google_auth_export.xlsx",
        custom_headers=custom_headers
    )

    task = db.get_task(task_id)
    assert task is not None
    assert task["custom_headers"] is not None
    saved_headers = task["custom_headers"] if isinstance(task["custom_headers"], dict) else json.loads(task["custom_headers"])
    assert "test_auth_cookie=12345" in saved_headers.get("Cookie", "")
    assert "drive.google.com" in saved_headers.get("Referer", "")

    # Execute download with forwarded headers
    downloader = HttpDownloader(db, sm)
    res = await downloader.download_task(task_id)
    assert res.get("status") == "COMPLETED" or "final_path" in res

    task = db.get_task(task_id)
    assert task["status"] == "COMPLETED"
    dest_file = dest_dir / "google_auth_export.xlsx"
    assert dest_file.exists()
    with open(dest_file, "rb") as f:
        assert f.read() == b"AUTHENTICATED_OK"


def test_default_browser_headers_built(resilience_env):
    """
    Test 6: Verifies default desktop browser headers (User-Agent, Accept, Accept-Language, Connection)
    are sent by default across probe and GET requests and overridden cleanly by Brave handoff headers.
    """
    db, sm, dest_dir, cfg = resilience_env
    dl = HttpDownloader(db, sm)

    default_hdrs = dl._build_default_headers()
    assert "Mozilla/5.0" in default_hdrs["User-Agent"]
    assert default_hdrs["Accept"] == "*/*"
    assert "en-US" in default_hdrs["Accept-Language"]
    assert default_hdrs["Connection"].lower() == "keep-alive"

    custom_hdrs = dl._build_default_headers({"User-Agent": "BraveCustomUA", "Cookie": "sid=1"})
    assert custom_hdrs["User-Agent"] == "BraveCustomUA"
    assert custom_hdrs["Cookie"] == "sid=1"
    assert "en-US" in custom_hdrs["Accept-Language"]


@pytest.mark.asyncio
async def test_midstream_disconnect_automatic_offset_retry(resilience_server, resilience_env):
    """
    Test 7: Server intentionally closes TCP socket mid-transfer (triggering ClientPayloadError /
    ServerDisconnectedError). Downloader must automatically retry with backoff from the exact
    flushed disk byte offset and produce a byte-for-byte SHA-256 match.
    """
    db, sm, dest_dir, cfg = resilience_env
    downloader = HttpDownloader(db, sm)
    url = f"{resilience_server}/drop-midstream"

    task_id = "test_drop_retry"
    staging_path = sm.allocate_task_staging(task_id)
    db.add_task({
        "id": task_id,
        "url": url,
        "filename": "download.bin",
        "destination": str(dest_dir),
        "staging_path": str(staging_path),
        "engine_type": "HTTP",
        "status": "QUEUED",
        "total_bytes": 0,
        "num_segments": 1
    })

    res = await downloader.download_task(task_id)
    assert res.get("status") == "COMPLETED" or "final_path" in res

    task = db.get_task(task_id)
    assert task["status"] == "COMPLETED"
    assert task["resumable"] == 1
    assert task["filename"] == "recovered_stream.bin"

    dest_file = dest_dir / "recovered_stream.bin"
    assert dest_file.exists()
    expected_sha256 = hashlib.sha256(RESILIENCE_PAYLOAD).hexdigest()
    actual_sha256 = hashlib.sha256(dest_file.read_bytes()).hexdigest()
    assert actual_sha256 == expected_sha256
