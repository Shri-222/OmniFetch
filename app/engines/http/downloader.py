"""
OmniFetch High-Speed Multi-Segment HTTP/HTTPS Engine
Features:
- Up to 16 parallel Range chunk connections via aiohttp.
- Crash-proof pause & resume persistence in SQLite.
- Live transfer speed & smoothed ETA calculation.
- Dynamic single-stream fallback for chunked/unknown-size streams and unseekable servers.
- Automatic certifi TLS certificate verification context.
- Robust RFC 5987 / Content-Disposition / MIME filename detection.
"""

import os
import sys
import time
import json
import asyncio
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs
import aiohttp

from ...core.logger import get_logger
from ...core.ssl_context import get_ssl_context

logger = get_logger("http_engine")

CHUNK_SIZE = 64 * 1024  # 64 KB read buffer

TRANSIENT_HTTP_EXCEPTIONS = (
    aiohttp.ServerDisconnectedError,
    aiohttp.ClientPayloadError,
    aiohttp.ClientOSError,
    aiohttp.ClientConnectionError,
    asyncio.TimeoutError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
)
RETRY_BACKOFF_SECONDS = [0.5, 1.0, 2.0, 4.0, 6.0]

class NonRetryableHttpError(RuntimeError):
    """Raised on permanent HTTP 4xx errors that should fail immediately without retries."""


class LinkExpiredError(NonRetryableHttpError):
    """Raised when a partial download hits HTTP 401/403/410 or unexpected HTML auth wall."""


class RangeMismatchError(RuntimeError):
    """Raised when a resumed Range segment receives HTTP 200 OK (ETag/If-Range mismatch)."""

    def __init__(self, message: str, mutated: bool = False, new_etag: str | None = None, new_last_modified: str | None = None):
        super().__init__(message)
        self.mutated = mutated
        self.new_etag = new_etag
        self.new_last_modified = new_last_modified


def parse_url_expiry(url: str | None) -> float | None:
    """Extracts unix expiration timestamp from common signed-URL query parameters."""
    if not url or not isinstance(url, str):
        return None
    try:
        qs = parse_qs(urlparse(url).query, keep_blank_values=False)
        lower_qs = {k.lower(): v for k, v in qs.items() if v}

        # AWS S3 SigV4: X-Amz-Date (YYYYMMDDTHHMMSSZ) + X-Amz-Expires (seconds)
        amz_date = (lower_qs.get("x-amz-date") or [None])[0]
        amz_exp = (lower_qs.get("x-amz-expires") or [None])[0]
        if amz_date and amz_exp and str(amz_exp).isdigit():
            try:
                dt = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                return dt.timestamp() + int(amz_exp)
            except Exception:
                pass

        # Unix epoch keys: Expires, exp, e
        for key in ("expires", "exp"):
            val = (lower_qs.get(key) or [None])[0]
            if val:
                try:
                    num = float(val)
                    if num > 1e12:  # ms -> s
                        num /= 1000.0
                    if num > 1e8:
                        return num
                except Exception:
                    pass

        # Azure SAS `se` (ISO UTC timestamp)
        se_val = (lower_qs.get("se") or [None])[0]
        if se_val:
            try:
                iso = se_val.replace("Z", "+00:00")
                return datetime.fromisoformat(iso).timestamp()
            except Exception:
                pass
    except Exception:
        pass
    return None


def _get_if_range_value(task: dict | None) -> str | None:
    """Selects RFC-7233 If-Range validator, preferring strong ETag over Last-Modified."""
    if not task:
        return None
    etag = (task.get("etag") or "").strip()
    last_mod = (task.get("last_modified") or "").strip()
    if etag and not etag.startswith("W/"):
        return etag
    if last_mod:
        return last_mod
    return etag or None


def _is_unexpected_html_page(content_type: str | None, filename: str | None, url: str | None) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct not in ("text/html", "application/xhtml+xml"):
        return False
    fname_low = (filename or "").lower()
    if fname_low.endswith((".html", ".htm", ".xhtml")):
        return False
    try:
        path_low = urlparse(url or "").path.lower()
        if path_low.endswith((".html", ".htm", ".xhtml")):
            return False
    except Exception:
        pass
    return True

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
CLIENT_FALLBACK_USER_AGENT = "OmniFetch/1.0"

CUSTOM_MIME_EXTENSIONS = {
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/avif": ".avif",
    "video/webm": ".webm",
    "audio/webm": ".weba",
    "application/x-zip-compressed": ".zip",
    "application/x-tar": ".tar",
    "application/x-gzip": ".gz",
    "application/x-bzip2": ".bz2",
    "application/x-7z-compressed": ".7z",
    "application/x-rar-compressed": ".rar",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/octet-stream": ""
}

class TokenBucketRateLimiter:
    def __init__(self, rate_kbs: int = 0):
        self.rate_bytes = rate_kbs * 1024
        self.capacity = max(self.rate_bytes, 64 * 1024)
        self.tokens = float(self.capacity)
        self.last_time = time.time()
        self._lock = asyncio.Lock()

    def set_rate(self, rate_kbs: int):
        self.rate_bytes = rate_kbs * 1024
        self.capacity = max(self.rate_bytes, 64 * 1024)

    @property
    def rate_limit_bytes_per_sec(self):
        return self.rate_bytes

    async def consume(self, num_bytes: int):
        if self.rate_bytes <= 0:
            return

        while num_bytes > 0:
            async with self._lock:
                now = time.time()
                elapsed = now - self.last_time
                self.last_time = now
                self.tokens = min(float(self.capacity), self.tokens + elapsed * self.rate_bytes)

                if self.tokens >= num_bytes:
                    self.tokens -= num_bytes
                    return
                else:
                    needed = num_bytes - self.tokens
                    wait_time = needed / self.rate_bytes
            await asyncio.sleep(min(wait_time, 0.2))

class HttpDownloader:
    def __init__(self, db, staging_manager, security_gate=None, min_split_threshold=512 * 1024, speed_limit_kbs: int = 0):
        self.db = db
        self.staging_manager = staging_manager
        self.security_gate = security_gate
        self.min_split_threshold = min_split_threshold
        self.rate_limiter = TokenBucketRateLimiter(speed_limit_kbs)

    def _build_default_headers(self, custom_headers: dict = None, user_agent_override: str = None) -> dict:
        """
        Builds realistic desktop browser headers by default so strict servers
        (e.g. ThinkBroadband) do not reject probe or segment GETs with HTTP 403.
        Custom headers forwarded from Brave override defaults when non-empty.
        """
        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        if custom_headers:
            for k, v in custom_headers.items():
                if v is not None and v != "":
                    headers[k] = v
        if user_agent_override:
            headers["User-Agent"] = user_agent_override
        return headers

    def _resolve_filename(self, url: str, disposition: str = "", content_type: str = "", caller_filename: str = None) -> str:
        """
        Resolves the real filename in strict priority:
        1. Non-generic caller filename (e.g. from Brave chrome.downloads)
        2. Content-Disposition header (RFC 5987 filename*= first, then filename=)
        3. Decoded final URL path basename (stripping query string and hashes)
        4. Derived extension from Content-Type MIME type if stem lacks extension
        """
        # 1. Caller filename if specific
        if caller_filename:
            clean_caller = caller_filename.strip().strip(' "\'')
            if clean_caller and clean_caller.lower() not in ("download.bin", "download", "uc", "file"):
                return clean_caller

        # 2. Content-Disposition header
        if disposition:
            # Check RFC 5987 filename*=UTF-8''... first
            if "filename*=" in disposition:
                try:
                    val = disposition.split("filename*=")[-1].split(";")[0].strip(' "\'')
                    if "''" in val:
                        _, encoded = val.split("''", 1)
                        decoded = unquote(encoded)
                        if decoded:
                            return os.path.basename(decoded)
                    else:
                        decoded = unquote(val)
                        if decoded:
                            return os.path.basename(decoded)
                except Exception as e:
                    logger.debug(f"Failed parsing filename* from {disposition}: {e}")

            if "filename=" in disposition:
                try:
                    parts = disposition.split("filename=")
                    raw = parts[-1].split(";")[0].strip(' "\'')
                    if raw and raw.lower() not in ("download.bin", "download"):
                        return os.path.basename(raw)
                except Exception as e:
                    logger.debug(f"Failed parsing filename from {disposition}: {e}")

        # 3. URL path basename
        candidate = ""
        try:
            parsed = urlparse(url)
            path = unquote(parsed.path)
            candidate = os.path.basename(path.rstrip("/"))
            # Strip query artifacts if any
            if "?" in candidate:
                candidate = candidate.split("?")[0]
        except Exception:
            pass

        if candidate and candidate.lower() not in ("download.bin", "download", "uc", "", "file"):
            # If candidate has an extension, return it
            if "." in candidate and len(candidate.rsplit(".", 1)[-1]) <= 6:
                return candidate
        else:
            candidate = "download"

        # 4. MIME type extension derivation
        if content_type:
            mime_clean = content_type.split(";")[0].strip().lower()
            ext = CUSTOM_MIME_EXTENSIONS.get(mime_clean)
            if ext is None:
                ext = mimetypes.guess_extension(mime_clean)
            if ext:
                if "." not in candidate:
                    candidate = f"{candidate}{ext}"
                elif not candidate.endswith(ext):
                    # Check if candidate has no recognizable extension
                    _, current_ext = os.path.splitext(candidate)
                    if not current_ext:
                        candidate = f"{candidate}{ext}"

        if not candidate or candidate.lower() in ("download.bin", "download"):
            candidate = "download.bin"

        return candidate

    async def probe(self, url: str, custom_headers: dict = None, caller_filename: str = None) -> dict:
        """
        Probes target URL to determine Content-Length, Accept-Ranges, Content-Type, ETag, and filename.
        Handles redirects and uses adaptive fallback:
        1) HEAD with primary headers
        2) GET Range: bytes=0-0 with primary headers
        3) On ServerDisconnectedError / 403 / 406: retry GET Range: bytes=0-0 with OmniFetch/1.0 UA
        4) On Range rejection (403/406/416): retry clean non-Range GET without reading full body
        """
        if url.startswith("blob:") or url.startswith("data:"):
            return {
                "total_bytes": 0,
                "accept_ranges": False,
                "filename": caller_filename or "download.bin",
                "status": 0,
                "error": "blob: and data: URLs are internal browser memory objects and cannot be downloaded externally."
            }

        primary_headers = self._build_default_headers(custom_headers)
        timeout = aiohttp.ClientTimeout(total=25, connect=15, sock_read=20)
        connector = aiohttp.TCPConnector(ssl=get_ssl_context(), limit_per_host=8, ttl_dns_cache=300)

        def _extract_probe_result(resp, used_ua: str, allow_range_from_cr: bool = True) -> dict:
            f_url = str(resp.url)
            disp = resp.headers.get("Content-Disposition", "")
            ctype = resp.headers.get("Content-Type", "")
            etag = resp.headers.get("ETag") or resp.headers.get("Etag")
            last_mod = resp.headers.get("Last-Modified")
            tot = 0
            acc_ranges = resp.headers.get("Accept-Ranges", "").lower() == "bytes"
            cr = resp.headers.get("Content-Range", "")
            if allow_range_from_cr and "/" in cr:
                tot_str = cr.split("/")[-1].strip()
                if tot_str.isdigit():
                    tot = int(tot_str)
                    acc_ranges = True
            if tot <= 0 and (resp.status == 200 or resp.request_info.method == "HEAD"):
                cl = resp.headers.get("Content-Length")
                if cl and cl.isdigit():
                    tot = int(cl)
            res_name = self._resolve_filename(f_url, disp, ctype, caller_filename)
            return {
                "total_bytes": tot,
                "accept_ranges": acc_ranges,
                "filename": res_name,
                "content_type": ctype,
                "final_url": f_url,
                "status": resp.status,
                "etag": etag,
                "last_modified": last_mod,
                "expires_at": parse_url_expiry(url) or parse_url_expiry(f_url),
                "effective_user_agent": used_ua,
            }

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            final_url = url
            disposition = ""
            content_type = ""
            total_bytes = 0
            accept_ranges = False
            last_err = None
            need_ua_fallback = False

            final_http_status = 0
            # 1. Try HEAD request first with primary headers
            try:
                async with session.head(url, headers=primary_headers, allow_redirects=True) as resp:
                    final_http_status = resp.status
                    res = _extract_probe_result(resp, primary_headers["User-Agent"], allow_range_from_cr=False)
                    final_url = res["final_url"]
                    content_type = res["content_type"]
                    total_bytes = res["total_bytes"]
                    accept_ranges = res["accept_ranges"]
                    disposition = resp.headers.get("Content-Disposition", "")
                    if resp.status < 400 and (total_bytes > 0 or accept_ranges) and res["filename"] != "download.bin":
                        return res
                    if resp.status in (403, 406):
                        need_ua_fallback = True
            except TRANSIENT_HTTP_EXCEPTIONS as e:
                logger.debug(f"HEAD probe transient failure for {url}: {e}")
                last_err = e
                need_ua_fallback = True
            except Exception as e:
                logger.debug(f"HEAD probe failed for {url}: {e}")
                last_err = e

            # 2. Fallback to GET with Range: bytes=0-0 (primary headers)
            range_rejected = False
            try:
                get_headers = dict(primary_headers)
                get_headers["Range"] = "bytes=0-0"
                async with session.get(url, headers=get_headers, allow_redirects=True) as resp:
                    final_http_status = resp.status
                    if resp.status < 400:
                        return _extract_probe_result(resp, primary_headers["User-Agent"])
                    if resp.status in (403, 406, 416):
                        need_ua_fallback = True
                        range_rejected = (resp.status == 416)
                    last_err = RuntimeError(f"HTTP {resp.status} {resp.reason}")
            except TRANSIENT_HTTP_EXCEPTIONS as e:
                logger.debug(f"GET Range probe transient failure for {url}: {e}")
                last_err = e
                need_ua_fallback = True
            except Exception as e:
                logger.warning(f"GET probe failed for {url}: {e}")
                last_err = e

            # 3. Adaptive UA fallback (e.g. Hetzner nginx drops Mozilla/* and HEAD, serves 206 to OmniFetch/1.0)
            if need_ua_fallback and primary_headers.get("User-Agent", "") != CLIENT_FALLBACK_USER_AGENT:
                client_headers = self._build_default_headers(custom_headers, user_agent_override=CLIENT_FALLBACK_USER_AGENT)
                if not range_rejected:
                    try:
                        r_headers = dict(client_headers)
                        r_headers["Range"] = "bytes=0-0"
                        async with session.get(url, headers=r_headers, allow_redirects=True) as resp:
                            final_http_status = resp.status
                            if resp.status < 400:
                                logger.info(f"Adaptive UA fallback ({CLIENT_FALLBACK_USER_AGENT}) succeeded for {url}")
                                return _extract_probe_result(resp, CLIENT_FALLBACK_USER_AGENT)
                            if resp.status == 416:
                                range_rejected = True
                            last_err = RuntimeError(f"HTTP {resp.status} {resp.reason}")
                    except Exception as e:
                        logger.debug(f"Adaptive Range GET probe failed for {url}: {e}")
                        last_err = e

                # 4. Fallback non-Range GET (reading headers only) if Range header itself caused 403/406/416
                for ua_headers in (client_headers, primary_headers):
                    try:
                        async with session.get(url, headers=ua_headers, allow_redirects=True) as resp:
                            final_http_status = resp.status
                            if resp.status < 400:
                                return _extract_probe_result(resp, ua_headers["User-Agent"], allow_range_from_cr=False)
                            last_err = RuntimeError(f"HTTP {resp.status} {resp.reason}")
                    except Exception as e:
                        last_err = e

            logger.warning(f"GET probe failed for {url}: {last_err}")
            return {
                "total_bytes": total_bytes,
                "accept_ranges": accept_ranges,
                "filename": self._resolve_filename(final_url, disposition, content_type, caller_filename),
                "content_type": content_type,
                "final_url": final_url,
                "status": final_http_status,
                "etag": None,
                "last_modified": None,
                "expires_at": parse_url_expiry(url) or parse_url_expiry(final_url),
                "effective_user_agent": None,
                "error": str(last_err or "Probe failed"),
            }

    async def _finalize_staged_file(self, task_id: str, staged_file: Path, filename: str):
        """Runs Stage 3 CyberShield Gate or moves verified staged file to user destination."""
        task_row = self.db.get_task(task_id)
        dest_dir = task_row["destination"]
        if self.security_gate:
            self.db.update_task_status(task_id, "SCANNING")
            gate_res = self.security_gate.evaluate_post_download(
                task_id=task_id,
                staged_file_path=str(staged_file),
                destination_dir=dest_dir
            )
            return gate_res

        final_path = self.staging_manager.move_to_destination(str(staged_file), dest_dir)
        self.db.update_task_status(task_id, "COMPLETED")
        return {"status": "COMPLETED", "final_path": final_path, "filename": filename}

    async def download_task(self, task_id, progress_callback=None, cancel_token=None, _mutated_restart=False):
        """
        Executes download for a task using multi-segment connections or fallback single stream.
        Handles cold-restart recovery directly for interrupted STAGED/SCANNING tasks,
        If-Range validation, and LINK EXPIRED transitions on 401/403/410 during resume.
        """
        task = self.db.get_task(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        url = task["url"]
        filename = task.get("filename") or "download.bin"
        total_bytes = task.get("total_bytes", 0)
        num_segments = task.get("num_segments", 1)

        # Cold-restart recovery when crashed during STAGED / SCANNING after .part files were stitched
        if task.get("status") in ("STAGED", "SCANNING") and self.staging_manager.staged_file_exists(task_id, filename):
            staged_file = self.staging_manager.get_staged_file_path(task_id, filename)
            logger.info(f"Task {task_id}: Resuming interrupted Stage 3 scan directly on {staged_file}")
            return await self._finalize_staged_file(task_id, staged_file, filename)

        custom_headers = {}
        if task.get("custom_headers"):
            try:
                c = json.loads(task["custom_headers"]) if isinstance(task["custom_headers"], str) else task["custom_headers"]
                if isinstance(c, dict):
                    custom_headers = c
            except Exception:
                pass

        # Pre-flight check: reject blob: and data: immediately
        if url.startswith("blob:") or url.startswith("data:"):
            err_msg = "blob: and data: URLs are internal browser memory objects and cannot be downloaded externally."
            self.db.update_task_status(task_id, "FAILED", error_message=err_msg)
            raise ValueError(err_msg)

        # Persist origin_referer and token expiry metadata upfront
        init_updates = {}
        if not task.get("origin_referer") and custom_headers.get("Referer"):
            init_updates["origin_referer"] = custom_headers.get("Referer")
        parsed_exp = parse_url_expiry(url)
        if parsed_exp and task.get("expires_at") != parsed_exp:
            init_updates["expires_at"] = parsed_exp
        if init_updates:
            self.db.update_task_fields(task_id, **init_updates)

        # Check if segments already exist from a paused or pre-allocated task
        existing_segs = self.db.get_segments(task_id)
        accept_ranges = len(existing_segs) > 1
        if accept_ranges:
            self.db.update_task_resumable(task_id, 1)

        # Detect whether partial payload already exists on disk/DB
        part0_path = self.staging_manager.get_segment_path(task_id, 0)
        has_partial_bytes = (
            (task.get("downloaded_bytes", 0) or 0) > 0
            or (part0_path.exists() and part0_path.stat().st_size > 0)
            or any(
                (self.staging_manager.get_segment_path(task_id, s["segment_index"]).exists()
                 and self.staging_manager.get_segment_path(task_id, s["segment_index"]).stat().st_size > 0)
                for s in existing_segs
            )
        )

        # Pre-probe if size is unknown, filename is generic, or multi-segment is requested but range support is not yet verified
        if total_bytes <= 0 or filename in ("download.bin", "download", "uc", "", None) or (num_segments > 1 and not accept_ranges):
            logger.info(f"Task {task_id}: Pre-probing {url} for size, filename, and range support...")
            probe_res = await self.probe(url, custom_headers=custom_headers, caller_filename=filename)

            if probe_res.get("error"):
                logger.warning(f"Task {task_id}: Probe returned error: {probe_res['error']}")

            probe_status = probe_res.get("status", 0)
            if has_partial_bytes and (
                probe_status in (401, 403, 410)
                or (probe_status in (200, 206) and _is_unexpected_html_page(probe_res.get("content_type"), filename, url))
            ):
                exp_msg = f"Link expired (HTTP {probe_status or 200}) — right-click to Refresh Download Address"
                logger.warning(f"Task {task_id}: {exp_msg}")
                self.db.update_task_status(task_id, "LINK EXPIRED", error_message=exp_msg)
                return {"status": "LINK EXPIRED", "error": exp_msg}

            field_updates = {}
            if probe_res.get("effective_user_agent") and probe_res["effective_user_agent"] != custom_headers.get("User-Agent"):
                if probe_res["effective_user_agent"] == CLIENT_FALLBACK_USER_AGENT or "User-Agent" not in custom_headers:
                    custom_headers["User-Agent"] = probe_res["effective_user_agent"]
                    field_updates["custom_headers"] = custom_headers
            if probe_res.get("etag"):
                field_updates["etag"] = probe_res["etag"]
            if probe_res.get("last_modified"):
                field_updates["last_modified"] = probe_res["last_modified"]
            if probe_res.get("final_url"):
                field_updates["final_url"] = probe_res["final_url"]
            if probe_res.get("expires_at"):
                field_updates["expires_at"] = probe_res["expires_at"]
            if field_updates:
                self.db.update_task_fields(task_id, **field_updates)

            if probe_res.get("filename") and probe_res["filename"] != "download.bin":
                filename = probe_res["filename"]
                self.db.update_task_filename(task_id, filename)
                logger.info(f"Task {task_id}: Resolved filename -> '{filename}'")

            if probe_res.get("total_bytes", 0) > 0:
                total_bytes = probe_res["total_bytes"]
                self.db.update_task_progress(task_id, task.get("downloaded_bytes", 0) or 0, total_bytes=total_bytes)
                logger.info(f"Task {task_id}: Resolved total size -> {total_bytes} bytes")

            if probe_res.get("accept_ranges"):
                accept_ranges = True
                self.db.update_task_resumable(task_id, 1)
            elif not probe_res.get("error") and probe_status > 0:
                self.db.update_task_resumable(task_id, 0)

        # Notify initial progress with resolved info
        if progress_callback:
            progress_callback({
                "task_id": task_id,
                "downloaded": task.get("downloaded_bytes", 0) or 0,
                "total": total_bytes,
                "speed": 0.0,
                "eta": 0
            })

        try:
            # Decide download strategy: Single-Stream Fallback vs Multi-Segment
            if total_bytes <= 0 or not accept_ranges or num_segments <= 1 or total_bytes < 1024 * 1024:
                logger.info(f"Task {task_id}: Using Single-Stream download fallback (total_bytes={total_bytes}, accept_ranges={accept_ranges})...")
                return await self._download_single_stream(
                    task_id=task_id,
                    url=url,
                    filename=filename,
                    total_bytes=total_bytes,
                    custom_headers=custom_headers,
                    progress_callback=progress_callback,
                    cancel_token=cancel_token
                )
            else:
                logger.info(f"Task {task_id}: Using Multi-Segment parallel download ({num_segments} connections)...")
                return await self._download_multi_segment(
                    task_id=task_id,
                    url=url,
                    filename=filename,
                    total_bytes=total_bytes,
                    num_segments=num_segments,
                    custom_headers=custom_headers,
                    progress_callback=progress_callback,
                    cancel_token=cancel_token
                )
        except RangeMismatchError as mismatch_err:
            if not _mutated_restart and mismatch_err.mutated:
                logger.warning(f"Task {task_id}: Remote file mutated (If-Range -> 200 OK); resetting staging cleanly and restarting from byte 0.")
                # Cleanly delete partial segment files and DB rows without appending onto stale parts
                staging_task_dir = self.staging_manager.allocate_task_staging(task_id)
                for p in staging_task_dir.glob("*.part"):
                    try:
                        p.unlink()
                    except Exception:
                        pass
                with self.db._lock, self.db.conn:
                    self.db.conn.execute("DELETE FROM segments WHERE task_id = ?;", (task_id,))
                self.db.update_task_progress(task_id, 0, total_bytes=0, speed_bps=0.0, eta_seconds=0)
                self.db.update_task_fields(
                    task_id,
                    total_bytes=0,
                    etag=mismatch_err.new_etag,
                    last_modified=mismatch_err.new_last_modified,
                )
                return await self.download_task(
                    task_id,
                    progress_callback=progress_callback,
                    cancel_token=cancel_token,
                    _mutated_restart=True,
                )
            self.db.update_task_status(task_id, "FAILED", error_message=str(mismatch_err))
            raise

    async def _download_single_stream(self, task_id, url, filename, total_bytes, custom_headers, progress_callback=None, cancel_token=None):
        """
        Executes robust single-stream GET download for chunked streams, dynamic exports, or servers lacking Range support.
        Automatically retries transient disconnects from the exact flushed disk offset when resumable.
        """
        part_path = self.staging_manager.get_segment_path(task_id, 0)
        task_row_init = self.db.get_task(task_id)
        if task_row_init and task_row_init.get("resumable") == 0 and part_path.exists():
            # Non-resumable stream cannot resume from partial offset; clean restart from byte 0
            try:
                part_path.unlink()
            except Exception:
                pass

        downloaded_bytes = part_path.stat().st_size if part_path.exists() else 0
        self.db.update_task_status(task_id, "DOWNLOADING")

        timeout = aiohttp.ClientTimeout(total=None, connect=20, sock_read=30)
        connector = aiohttp.TCPConnector(ssl=get_ssl_context(), limit=4, ttl_dns_cache=300)
        speed_window = []
        last_progress_time = time.time()
        last_downloaded = downloaded_bytes
        ua_override = None

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for attempt in range(len(RETRY_BACKOFF_SECONDS) + 1):
                    if cancel_token and cancel_token.get("is_cancelled"):
                        logger.info(f"Task {task_id}: Single-stream paused by user.")
                        self.db.update_task_status(task_id, "PAUSED")
                        return {"status": "PAUSED"}

                    downloaded_bytes = part_path.stat().st_size if part_path.exists() else 0
                    mode = "ab" if downloaded_bytes > 0 else "wb"
                    req_headers = self._build_default_headers(custom_headers, user_agent_override=ua_override)
                    task_snapshot = self.db.get_task(task_id)
                    has_prior_progress = downloaded_bytes > 0 or ((task_snapshot or {}).get("downloaded_bytes", 0) or 0) > 0
                    if downloaded_bytes > 0:
                        req_headers["Range"] = f"bytes={downloaded_bytes}-"
                        if_range_val = _get_if_range_value(task_snapshot)
                        if if_range_val:
                            req_headers["If-Range"] = if_range_val

                    try:
                        async with session.get(url, headers=req_headers, allow_redirects=True) as resp:
                            if resp.status in (401, 403, 410) and has_prior_progress:
                                err_msg = f"Link expired (HTTP {resp.status} {resp.reason}) — right-click to Refresh Download Address"
                                raise LinkExpiredError(err_msg)
                            if 400 <= resp.status < 500:
                                err_msg = f"HTTP {resp.status} {resp.reason}"
                                raise NonRetryableHttpError(err_msg)
                            if resp.status not in (200, 206):
                                err_msg = f"HTTP {resp.status} {resp.reason}"
                                raise RuntimeError(err_msg)

                            content_type = resp.headers.get("Content-Type", "")
                            if has_prior_progress and _is_unexpected_html_page(content_type, filename, url):
                                raise LinkExpiredError("Link expired (server returned HTML login/error page during resume)")

                            # Update validators if server returned new ETag / Last-Modified
                            val_updates = {}
                            if resp.headers.get("ETag"):
                                val_updates["etag"] = resp.headers.get("ETag")
                            if resp.headers.get("Last-Modified"):
                                val_updates["last_modified"] = resp.headers.get("Last-Modified")
                            if str(resp.url):
                                val_updates["final_url"] = str(resp.url)
                            if val_updates:
                                self.db.update_task_fields(task_id, **val_updates)

                            # Determine resumability from live response
                            if resp.status == 206 or resp.headers.get("Accept-Ranges", "").lower() == "bytes":
                                self.db.update_task_resumable(task_id, 1)
                            else:
                                cur_row = self.db.get_task(task_id)
                                if cur_row and cur_row.get("resumable") == -1:
                                    self.db.update_task_resumable(task_id, 0)

                            # If server ignored Range/If-Range and returned 200 OK from byte 0, restart cleanly without appending
                            if downloaded_bytes > 0 and resp.status == 200:
                                logger.info(f"Task {task_id}: Server returned HTTP 200 OK instead of 206; truncating and restarting from byte 0.")
                                mode = "wb"
                                downloaded_bytes = 0
                                last_downloaded = 0

                            # Inspect live response headers to update filename and size if still generic
                            disposition = resp.headers.get("Content-Disposition", "")
                            content_type = resp.headers.get("Content-Type", "")
                            final_url = str(resp.url)

                            new_filename = self._resolve_filename(final_url, disposition, content_type, caller_filename=filename)
                            if new_filename and new_filename != filename:
                                filename = new_filename
                                self.db.update_task_filename(task_id, filename)
                                logger.info(f"Task {task_id}: Updated filename from stream headers -> '{filename}'")

                            if total_bytes <= 0:
                                cl = resp.headers.get("Content-Length")
                                if cl and cl.isdigit():
                                    total_bytes = int(cl)
                                    self.db.update_task_progress(task_id, downloaded_bytes, total_bytes=total_bytes)

                            with open(part_path, mode) as f:
                                async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                                    if cancel_token and cancel_token.get("is_cancelled"):
                                        f.flush()
                                        logger.info(f"Task {task_id}: Single-stream paused by user.")
                                        self.db.update_task_progress(task_id, downloaded_bytes, total_bytes=total_bytes, speed_bps=0.0, eta_seconds=0)
                                        self.db.update_task_status(task_id, "PAUSED")
                                        return {"status": "PAUSED"}

                                    await self.rate_limiter.consume(len(chunk))
                                    f.write(chunk)
                                    f.flush()
                                    downloaded_bytes += len(chunk)

                                    now = time.time()
                                    dt = now - last_progress_time
                                    if dt >= 0.15 or (last_downloaded == 0 and downloaded_bytes >= 16384):
                                        delta = max(0, downloaded_bytes - last_downloaded)
                                        speed_bps = delta / max(dt, 0.01)
                                        speed_window.append(speed_bps)
                                        if len(speed_window) > 4:
                                            speed_window.pop(0)
                                        smooth_speed = sum(speed_window) / len(speed_window)

                                        rem_bytes = max(0, total_bytes - downloaded_bytes) if total_bytes > 0 else 0
                                        eta_sec = int(rem_bytes / smooth_speed) if smooth_speed > 0 and total_bytes > 0 else 0

                                        self.db.update_task_progress(
                                            task_id=task_id,
                                            downloaded_bytes=downloaded_bytes,
                                            total_bytes=total_bytes,
                                            speed_bps=smooth_speed,
                                            eta_seconds=eta_sec
                                        )

                                        if progress_callback:
                                            progress_callback({
                                                "task_id": task_id,
                                                "downloaded": downloaded_bytes,
                                                "total": total_bytes,
                                                "speed": smooth_speed,
                                                "eta": eta_sec
                                            })

                                        last_progress_time = now
                                        last_downloaded = downloaded_bytes

                            # Clean EOF reached
                            break

                    except TRANSIENT_HTTP_EXCEPTIONS as e:
                        if cancel_token and cancel_token.get("is_cancelled"):
                            self.db.update_task_status(task_id, "PAUSED")
                            return {"status": "PAUSED"}
                        flushed = part_path.stat().st_size if part_path.exists() else 0
                        self.db.update_task_progress(task_id, flushed, total_bytes=total_bytes, speed_bps=0.0, eta_seconds=0)
                        if (
                            isinstance(e, aiohttp.ServerDisconnectedError)
                            and flushed == 0
                            and req_headers.get("User-Agent", "").startswith("Mozilla/")
                            and ua_override != CLIENT_FALLBACK_USER_AGENT
                        ):
                            ua_override = CLIENT_FALLBACK_USER_AGENT
                            custom_headers["User-Agent"] = ua_override
                            self.db.update_task_fields(task_id, custom_headers=custom_headers)
                            logger.info(f"Task {task_id}: Switched UA to {ua_override} after ServerDisconnectedError at 0 bytes.")
                        if attempt < len(RETRY_BACKOFF_SECONDS):
                            delay = RETRY_BACKOFF_SECONDS[attempt]
                            logger.warning(
                                f"Task {task_id}: Transient stream error ({type(e).__name__}: {e}) at {flushed} bytes; "
                                f"retrying in {delay}s (attempt {attempt + 1}/{len(RETRY_BACKOFF_SECONDS)})"
                            )
                            await asyncio.sleep(delay)
                            continue
                        raise

            # EOF reached: set total_bytes to downloaded_bytes if unknown
            if total_bytes <= 0:
                total_bytes = downloaded_bytes

            self.db.update_task_progress(task_id, downloaded_bytes, total_bytes=total_bytes, speed_bps=0.0, eta_seconds=0)

            # Record single segment
            segs = [{
                "index": 0,
                "segment_index": 0,
                "start": 0,
                "start_byte": 0,
                "end": total_bytes - 1 if total_bytes > 0 else 0,
                "end_byte": total_bytes - 1 if total_bytes > 0 else 0,
                "current": total_bytes,
                "current_byte": total_bytes,
                "status": "COMPLETED"
            }]
            self.db.save_segments(task_id, segs)

            # Stage 2 Assembly
            self.db.update_task_status(task_id, "STAGED")
            staged_file = self.staging_manager.assemble_segments(
                task_id=task_id,
                filename=filename,
                segments_metadata=segs
            )

            return await self._finalize_staged_file(task_id, Path(staged_file), filename)

        except LinkExpiredError as e:
            logger.warning(f"Task {task_id}: Link expired during single-stream resume: {e}")
            self.db.update_task_status(task_id, "LINK EXPIRED", error_message=str(e))
            return {"status": "LINK EXPIRED", "error": str(e)}
        except Exception as e:
            logger.error(f"Task {task_id}: Single-stream download error: {e}", exc_info=True)
            self.db.update_task_status(task_id, "FAILED", error_message=str(e))
            raise

    async def _download_multi_segment(self, task_id, url, filename, total_bytes, num_segments, custom_headers, progress_callback=None, cancel_token=None):
        """
        Executes parallel multi-segment download with dynamic in-half splitting.
        """
        existing_segs = self.db.get_segments(task_id)
        if not existing_segs:
            chunk_len = total_bytes // num_segments
            segs = []
            for i in range(num_segments):
                start = i * chunk_len
                end = (start + chunk_len - 1) if i < num_segments - 1 else (total_bytes - 1)
                segs.append({
                    "index": i,
                    "start": start,
                    "end": end,
                    "current": start,
                    "status": "PENDING"
                })
            self.db.save_segments(task_id, segs)
            existing_segs = self.db.get_segments(task_id)

        self.db.update_task_status(task_id, "DOWNLOADING")

        active_segments = {}
        for s in existing_segs:
            idx = s["segment_index"]
            is_done = (s["status"] == "COMPLETED") or (s["end_byte"] > 0 and s["current_byte"] >= s["end_byte"])
            active_segments[idx] = {
                "segment_index": idx,
                "start_byte": s["start_byte"],
                "end_byte": s["end_byte"],
                "current_byte": s["current_byte"],
                "status": "COMPLETED" if is_done else s["status"],
                "is_active": False,
                "retries": 0
            }

        split_lock = asyncio.Lock()
        min_split = self.min_split_threshold
        fatal_error = None

        async def get_or_split_segment():
            async with split_lock:
                if fatal_error:
                    return None

                for idx, s in sorted(active_segments.items()):
                    if not s["is_active"] and s["status"] != "COMPLETED":
                        if s["retries"] < 3:
                            if s["end_byte"] == 0 or s["current_byte"] <= s["end_byte"]:
                                s["is_active"] = True
                                s["status"] = "DOWNLOADING"
                                return s

                # Dynamic In-Half Split
                if total_bytes <= 0:
                    return None

                best_candidate = None
                max_rem = 0
                for idx, s in active_segments.items():
                    if s["is_active"] and s["end_byte"] > 0:
                        rem = s["end_byte"] - s["current_byte"] + 1
                        if rem > max_rem:
                            max_rem = rem
                            best_candidate = s

                if best_candidate and max_rem >= min_split:
                    cur_offset = best_candidate["current_byte"]
                    old_end = best_candidate["end_byte"]
                    half = (old_end - cur_offset + 1) // 2
                    midpoint = cur_offset + half - 1

                    if midpoint >= cur_offset and midpoint < old_end:
                        best_candidate["end_byte"] = midpoint
                        self.db.update_segment_range(task_id, best_candidate["segment_index"], end_byte=midpoint)

                        new_idx = max(active_segments.keys()) + 1
                        new_start = midpoint + 1
                        new_end = old_end
                        new_seg = {
                            "segment_index": new_idx,
                            "start_byte": new_start,
                            "end_byte": new_end,
                            "current_byte": new_start,
                            "status": "DOWNLOADING",
                            "is_active": True,
                            "retries": 0
                        }
                        active_segments[new_idx] = new_seg
                        self.db.add_segment(task_id, new_idx, new_start, new_end, new_start, status="DOWNLOADING")
                        return new_seg

                return None

        connector = aiohttp.TCPConnector(limit=max(num_segments * 2, 16), ssl=get_ssl_context(), ttl_dns_cache=300)
        headers = self._build_default_headers(custom_headers)

        timeout = aiohttp.ClientTimeout(total=None, connect=20, sock_read=30)

        speed_window = []
        last_progress_time = time.time()
        last_downloaded = sum(s["current_byte"] - s["start_byte"] for s in existing_segs)

        try:
            async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
                async def worker_loop():
                    nonlocal fatal_error
                    while not (cancel_token and cancel_token.get("is_cancelled")) and not fatal_error:
                        seg = await get_or_split_segment()
                        if not seg:
                            break
                        try:
                            await self._download_segment(
                                session=session,
                                task_id=task_id,
                                seg=seg,
                                custom_headers=custom_headers,
                                cancel_token=cancel_token,
                                split_lock=split_lock
                            )
                        except (NonRetryableHttpError, RangeMismatchError) as e:
                            logger.error(f"Task {task_id} segment {seg['segment_index']} aborted: {e}")
                            fatal_error = e
                            break
                        except Exception as e:
                            logger.error(f"Task {task_id} segment {seg['segment_index']} exhausted retries: {e}")
                            fatal_error = e
                            break
                        finally:
                            async with split_lock:
                                seg["is_active"] = False

                worker_count = max(1, min(num_segments, 16))
                worker_tasks = [asyncio.create_task(worker_loop()) for _ in range(worker_count)]

                async def track_progress():
                    nonlocal last_progress_time, last_downloaded
                    while any(not t.done() for t in worker_tasks):
                        await asyncio.sleep(0.1)
                        if cancel_token and cancel_token.get("is_cancelled"):
                            break
                        if fatal_error:
                            break

                        now = time.time()
                        dt = now - last_progress_time
                        segs = self.db.get_segments(task_id)
                        current_downloaded = sum(s["current_byte"] - s["start_byte"] for s in segs)

                        if dt >= 0.15 or (last_downloaded == 0 and current_downloaded >= 16384):
                            delta_bytes = max(0, current_downloaded - last_downloaded)
                            speed_bps = delta_bytes / max(dt, 0.01)
                            speed_window.append(speed_bps)
                            if len(speed_window) > 4:
                                speed_window.pop(0)
                            smooth_speed = sum(speed_window) / len(speed_window)

                            rem_bytes = max(0, total_bytes - current_downloaded)
                            eta_sec = int(rem_bytes / smooth_speed) if smooth_speed > 0 else 0

                            self.db.update_task_progress(
                                task_id=task_id,
                                downloaded_bytes=current_downloaded,
                                total_bytes=total_bytes,
                                speed_bps=smooth_speed,
                                eta_seconds=eta_sec
                            )

                            if progress_callback:
                                progress_callback({
                                    "task_id": task_id,
                                    "downloaded": current_downloaded,
                                    "total": total_bytes,
                                    "speed": smooth_speed,
                                    "eta": eta_sec
                                })

                            last_progress_time = now
                            last_downloaded = current_downloaded

                tracker = asyncio.create_task(track_progress())
                await asyncio.gather(*worker_tasks, return_exceptions=True)
                tracker.cancel()

            if fatal_error:
                err_msg = str(fatal_error)
                if isinstance(fatal_error, LinkExpiredError):
                    self.db.update_task_status(task_id, "LINK EXPIRED", error_message=err_msg)
                    return {"status": "LINK EXPIRED", "error": err_msg}
                if isinstance(fatal_error, RangeMismatchError):
                    raise fatal_error
                self.db.update_task_status(task_id, "FAILED", error_message=err_msg)
                raise fatal_error

            if cancel_token and cancel_token.get("is_cancelled"):
                self.db.update_task_status(task_id, "PAUSED")
                return {"status": "PAUSED"}

            segs = self.db.get_segments(task_id)
            all_done = all(s["status"] == "COMPLETED" or (s["end_byte"] > 0 and s["current_byte"] >= s["end_byte"]) for s in segs)
            if not all_done:
                err_msg = "Download interrupted before all segments completed."
                self.db.update_task_status(task_id, "FAILED", error_message=err_msg)
                raise RuntimeError(err_msg)

            # Stage 2 Assembly
            self.db.update_task_status(task_id, "STAGED")
            staged_file = self.staging_manager.assemble_segments(
                task_id=task_id,
                filename=filename,
                segments_metadata=segs
            )

            return await self._finalize_staged_file(task_id, Path(staged_file), filename)

        except LinkExpiredError as e:
            logger.warning(f"Task {task_id}: Link expired during multi-segment download: {e}")
            self.db.update_task_status(task_id, "LINK EXPIRED", error_message=str(e))
            return {"status": "LINK EXPIRED", "error": str(e)}
        except RangeMismatchError:
            raise
        except Exception as e:
            logger.error(f"Task {task_id}: Multi-segment error: {e}", exc_info=True)
            self.db.update_task_status(task_id, "FAILED", error_message=str(e))
            raise

    async def _download_segment(self, session, task_id, seg, custom_headers=None, cancel_token=None, split_lock=None):
        seg_idx = seg["segment_index"]
        part_path = self.staging_manager.get_segment_path(task_id, seg_idx)

        task_data = self.db.get_task(task_id)
        if not task_data:
            return

        for attempt in range(len(RETRY_BACKOFF_SECONDS) + 1):
            if cancel_token and cancel_token.get("is_cancelled"):
                self.db.update_segment_progress(task_id, seg_idx, seg["current_byte"], "PENDING")
                seg["status"] = "PENDING"
                return

            # Resume strictly from exact bytes flushed to disk for this segment
            disk_bytes = part_path.stat().st_size if part_path.exists() else 0
            start_byte = seg["start_byte"] + disk_bytes
            seg["current_byte"] = start_byte
            end_byte = seg["end_byte"]

            if end_byte > 0 and start_byte > end_byte:
                seg["status"] = "COMPLETED"
                self.db.update_segment_progress(task_id, seg_idx, start_byte, "COMPLETED")
                return

            mode = "ab" if disk_bytes > 0 else "wb"
            headers = self._build_default_headers(custom_headers)

            sent_range = False
            if end_byte > 0 and end_byte >= start_byte:
                headers["Range"] = f"bytes={start_byte}-{end_byte}"
                sent_range = True
            elif start_byte > 0:
                headers["Range"] = f"bytes={start_byte}-"
                sent_range = True

            if_range_val = _get_if_range_value(task_data)
            if sent_range and if_range_val:
                headers["If-Range"] = if_range_val

            has_partial_task = (
                disk_bytes > 0
                or (task_data.get("downloaded_bytes", 0) or 0) > 0
            )

            current = start_byte
            try:
                async with session.get(task_data["url"], headers=headers, allow_redirects=True) as resp:
                    if resp.status in (401, 403, 410) and has_partial_task:
                        err_msg = f"Link expired (HTTP {resp.status} {resp.reason}) — right-click to Refresh Download Address"
                        self.db.update_segment_progress(task_id, seg_idx, start_byte, "PENDING")
                        seg["status"] = "PENDING"
                        raise LinkExpiredError(err_msg)
                    if 400 <= resp.status < 500:
                        err_msg = f"HTTP {resp.status} {resp.reason}"
                        self.db.update_segment_progress(task_id, seg_idx, start_byte, "FAILED")
                        seg["status"] = "FAILED"
                        raise NonRetryableHttpError(f"Segment {seg_idx} failed: {err_msg}")
                    if resp.status not in (200, 206):
                        err_msg = f"HTTP {resp.status} {resp.reason}"
                        self.db.update_segment_progress(task_id, seg_idx, start_byte, "FAILED")
                        seg["status"] = "FAILED"
                        raise RuntimeError(f"Segment {seg_idx} failed: {err_msg}")

                    if has_partial_task and _is_unexpected_html_page(
                        resp.headers.get("Content-Type", ""),
                        task_data.get("filename"),
                        task_data.get("url"),
                    ):
                        self.db.update_segment_progress(task_id, seg_idx, start_byte, "PENDING")
                        seg["status"] = "PENDING"
                        raise LinkExpiredError("Link expired (server returned HTML login/error page during segment resume)")

                    # Critical IDM guard: if server returned 200 OK instead of 206 Partial Content
                    # when requesting a Range (e.g. If-Range mismatch on mutated resource), NEVER append!
                    if sent_range and resp.status == 200:
                        new_etag = resp.headers.get("ETag")
                        new_lm = resp.headers.get("Last-Modified")
                        old_etag = task_data.get("etag")
                        old_lm = task_data.get("last_modified")
                        mutated = bool(
                            (new_etag and old_etag and new_etag != old_etag)
                            or (new_lm and old_lm and new_lm != old_lm)
                            or (if_range_val is not None)
                        )
                        self.db.update_segment_progress(task_id, seg_idx, start_byte, "PENDING")
                        seg["status"] = "PENDING"
                        raise RangeMismatchError(
                            f"Segment {seg_idx} received HTTP 200 OK instead of 206 Partial Content (ETag/If-Range mismatch)",
                            mutated=mutated,
                            new_etag=new_etag,
                            new_last_modified=new_lm,
                        )

                    # Store initial ETag / Last-Modified if missing
                    val_updates = {}
                    if resp.headers.get("ETag") and not task_data.get("etag"):
                        val_updates["etag"] = resp.headers.get("ETag")
                    if resp.headers.get("Last-Modified") and not task_data.get("last_modified"):
                        val_updates["last_modified"] = resp.headers.get("Last-Modified")
                    if val_updates:
                        self.db.update_task_fields(task_id, **val_updates)

                    with open(part_path, mode) as f:
                        async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                            if cancel_token and cancel_token.get("is_cancelled"):
                                f.flush()
                                self.db.update_segment_progress(task_id, seg_idx, current, "PENDING")
                                seg["status"] = "PENDING"
                                return

                            await self.rate_limiter.consume(len(chunk))

                            curr_end = seg["end_byte"]
                            if curr_end > 0 and (current + len(chunk) - 1) > curr_end:
                                needed = max(0, curr_end - current + 1)
                                if needed > 0:
                                    f.write(chunk[:needed])
                                    f.flush()
                                    current += needed
                                seg["current_byte"] = current
                                seg["status"] = "COMPLETED"
                                self.db.update_segment_progress(task_id, seg_idx, current, "COMPLETED")
                                return

                            f.write(chunk)
                            f.flush()
                            current += len(chunk)
                            seg["current_byte"] = current
                            self.db.update_segment_progress(task_id, seg_idx, current, "DOWNLOADING")

                            if curr_end > 0 and current > curr_end:
                                break

                    seg["current_byte"] = current
                    seg["status"] = "COMPLETED"
                    self.db.update_segment_progress(task_id, seg_idx, current, "COMPLETED")
                    return

            except TRANSIENT_HTTP_EXCEPTIONS as e:
                disk_after = part_path.stat().st_size if part_path.exists() else 0
                flushed_offset = seg["start_byte"] + disk_after
                seg["current_byte"] = flushed_offset
                self.db.update_segment_progress(task_id, seg_idx, flushed_offset, "PENDING")

                if cancel_token and cancel_token.get("is_cancelled"):
                    return

                if attempt < len(RETRY_BACKOFF_SECONDS):
                    delay = RETRY_BACKOFF_SECONDS[attempt]
                    logger.warning(
                        f"Task {task_id} seg {seg_idx}: Transient disconnect ({type(e).__name__}: {e}) "
                        f"at byte {flushed_offset}; retrying in {delay}s (attempt {attempt + 1}/{len(RETRY_BACKOFF_SECONDS)})"
                    )
                    await asyncio.sleep(delay)
                    continue

                seg["status"] = "FAILED"
                self.db.update_segment_progress(task_id, seg_idx, flushed_offset, "FAILED")
                raise RuntimeError(f"Segment {seg_idx} failed after {len(RETRY_BACKOFF_SECONDS)} retries: {e}") from e
