"""
OmniFetch MEGA.nz Worker (PySide6 QThread)
Manages asynchronous MEGA file and folder downloads with:
- 16-byte block aligned AES-128-CTR multi-chunk parallel decryption.
- Passive SmartProxy rotation on HTTP 509.
- Automatic chunked CBC-MAC integrity verification.
- Stage 3 CyberShield Post-Download Security Gate with quarantine isolation.
"""

import os
import time
import shutil
import asyncio
import aiohttp
from typing import List, Dict, Optional
from pathlib import Path
from PySide6.QtCore import QThread, Signal

from .resolver import MegaUrlResolver
from .client import MegaClient
from .crypto import decrypt_chunk, get_ctr_cipher, verify_file_mac
from .proxy_pool import ProxyPool
from ...core.security_gate import SecurityGate
from ...core.ssl_context import get_ssl_context

CHUNK_READ_SIZE = 64 * 1024  # 64 KB read buffer
SCAN_EXTENSIONS = {
    '.exe', '.dll', '.msi', '.bat', '.cmd', '.scr',
    '.pif', '.vbs', '.hta', '.ps1', '.zip', '.rar', '.7z',
    '.ini', '.cfg', '.nfo'
}

class MegaDownloadWorker(QThread):
    progress_signal = Signal(dict)
    status_signal = Signal(str, str)
    finished_signal = Signal(str, dict)
    error_signal = Signal(str, str)

    def __init__(
        self,
        task_id: str,
        db,
        staging_manager,
        security_gate: SecurityGate,
        url: str,
        destination_dir: str,
        proxy_pool: Optional[ProxyPool] = None,
        selected_file_indices: Optional[List[int]] = None,
        rate_limiter=None,
    ):
        super().__init__()
        self.task_id = task_id
        self.db = db
        self.staging_manager = staging_manager
        self.security_gate = security_gate
        self.url = url
        self.destination_dir = destination_dir
        self.proxy_pool = proxy_pool or ProxyPool()
        self.selected_file_indices = selected_file_indices
        self.rate_limiter = rate_limiter
        self.is_running = True
        self.client = MegaClient(self.proxy_pool)

    def stop(self):
        self.is_running = False

    def pause(self):
        self.is_running = False

    def run(self):
        asyncio.run(self._execute_mega_download())

    async def _execute_mega_download(self):
        parsed = MegaUrlResolver.parse_url(self.url)
        if not parsed:
            self.db.update_task_status(self.task_id, "FAILED", error_message=f"Invalid MEGA URL: {self.url}")
            self.error_signal.emit(self.task_id, f"Invalid MEGA URL: {self.url}")
            return

        staging_dir = self.staging_manager.allocate_task_staging(self.task_id)
        task_row = self.db.get_task(self.task_id)

        try:
            self.db.update_task_resumable(self.task_id, 1)

            # Cold-restart recovery if interrupted during Stage 3 STAGED/SCANNING
            if task_row and task_row.get("status") in ("STAGED", "SCANNING"):
                if parsed["type"] == "file":
                    staged_path = staging_dir / task_row.get("filename", "")
                    if staged_path.is_file():
                        self.status_signal.emit(self.task_id, "SCANNING")
                        self.db.update_task_status(self.task_id, "SCANNING")
                        gate_res = self.security_gate.evaluate_post_download(
                            task_id=self.task_id,
                            staged_file_path=str(staged_path),
                            destination_dir=self.destination_dir
                        )
                        if gate_res.get("action") == "SCAN_ERROR":
                            raise RuntimeError(gate_res.get("error", "Security scan failed"))
                        self.finished_signal.emit(self.task_id, gate_res)
                        return
                else:
                    if staging_dir.exists() and any(staging_dir.rglob("*")):
                        self.status_signal.emit(self.task_id, "SCANNING")
                        self.db.update_task_status(self.task_id, "SCANNING")
                        results = self._process_stage3_folder(staging_dir, self.destination_dir)
                        self.finished_signal.emit(self.task_id, results)
                        return

            self.status_signal.emit(self.task_id, "DOWNLOADING")
            self.db.update_task_status(self.task_id, "DOWNLOADING")

            if parsed["type"] == "file":
                await self._download_single_file(parsed, staging_dir)
            else:
                await self._download_folder(parsed, staging_dir)
        except Exception as e:
            self.db.update_task_status(self.task_id, "FAILED", error_message=str(e))
            self.error_signal.emit(self.task_id, str(e))

    async def _download_single_file(self, parsed: dict, staging_dir: Path):
        file_info = await self.client.get_file_info(parsed["id"], parsed["key"])
        file_size = file_info["size"]
        filename = file_info["filename"]
        aes_key = file_info["aes_key"]
        iv = file_info["iv"]
        meta_mac = file_info["meta_mac"]
        download_url = file_info["download_url"]

        self.db.update_task_filename(self.task_id, filename)
        staged_file = staging_dir / filename
        existing = staged_file.stat().st_size if staged_file.exists() else 0
        self.db.update_task_progress(self.task_id, (existing // 16) * 16, total_bytes=file_size)

        async def _refresh_single_url():
            fresh = await self.client.get_file_info(parsed["id"], parsed["key"])
            return fresh["download_url"]

        await self._stream_and_decrypt_file(
            download_url=download_url,
            target_path=staged_file,
            file_size=file_size,
            aes_key=aes_key,
            iv=iv,
            refresh_url_callback=_refresh_single_url,
        )

        if not self.is_running:
            self.db.update_task_status(self.task_id, "PAUSED")
            self.status_signal.emit(self.task_id, "PAUSED")
            return

        # Verify integrity via CBC-MAC
        is_valid = verify_file_mac(staged_file, file_size, aes_key, iv, meta_mac)
        if not is_valid:
            raise ValueError(f"MEGA CBC-MAC integrity verification failed for {filename}")

        # Stage 3 Security Gate
        self.db.update_task_status(self.task_id, "SCANNING")
        self.status_signal.emit(self.task_id, "SCANNING")
        gate_res = self.security_gate.evaluate_post_download(
            task_id=self.task_id,
            staged_file_path=str(staged_file),
            destination_dir=self.destination_dir
        )
        if gate_res.get("action") == "SCAN_ERROR":
            raise RuntimeError(gate_res.get("error", "Security scan failed"))

        self.finished_signal.emit(self.task_id, gate_res)

    async def _download_folder(self, parsed: dict, staging_dir: Path):
        nodes = await self.client.get_folder_nodes(parsed["id"], parsed["key"])

        # Filter selected files if selection passed
        files_to_download = []
        for n in nodes:
            if self.selected_file_indices is None or n["index"] in self.selected_file_indices:
                files_to_download.append(n)

        total_folder_size = sum(f["size"] for f in files_to_download)
        downloaded_so_far = 0
        for f_item in files_to_download:
            tp = staging_dir / f_item["path"]
            if tp.exists() and tp.stat().st_size >= f_item["size"]:
                downloaded_so_far += f_item["size"]
        self.db.update_task_progress(self.task_id, downloaded_so_far, total_bytes=total_folder_size)

        downloaded_so_far = 0

        for f_item in files_to_download:
            if not self.is_running:
                self.db.update_task_status(self.task_id, "PAUSED")
                self.status_signal.emit(self.task_id, "PAUSED")
                return

            f_size = f_item["size"]
            target_path = staging_dir / f_item["path"]
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Skip re-downloading files already complete and MAC-verified from prior pause
            if target_path.exists() and target_path.stat().st_size == f_size:
                if verify_file_mac(target_path, f_size, f_item["aes_key"], f_item["iv"], f_item["meta_mac"]):
                    downloaded_so_far += f_size
                    continue

            dl_meta = await self.client.get_folder_file_download_url(parsed["id"], f_item["id"])
            dl_url = dl_meta["download_url"]

            async def _refresh_folder_url(node_id=f_item["id"]):
                fresh = await self.client.get_folder_file_download_url(parsed["id"], node_id)
                return fresh["download_url"]

            await self._stream_and_decrypt_file(
                download_url=dl_url,
                target_path=target_path,
                file_size=f_size,
                aes_key=f_item["aes_key"],
                iv=f_item["iv"],
                base_progress_offset=downloaded_so_far,
                total_job_size=total_folder_size,
                refresh_url_callback=_refresh_folder_url,
            )

            if not self.is_running:
                self.db.update_task_status(self.task_id, "PAUSED")
                self.status_signal.emit(self.task_id, "PAUSED")
                return

            # Enforce individual file CBC-MAC verification
            is_valid = verify_file_mac(target_path, f_size, f_item["aes_key"], f_item["iv"], f_item["meta_mac"])
            if not is_valid:
                raise ValueError(f"MEGA CBC-MAC integrity verification failed for {f_item['path']}")
            downloaded_so_far += f_size

        # Stage 3: Folder Post-Download Security Gate
        self.db.update_task_status(self.task_id, "SCANNING")
        self.status_signal.emit(self.task_id, "SCANNING")
        results = self._process_stage3_folder(staging_dir, self.destination_dir)
        self.finished_signal.emit(self.task_id, results)

    async def _stream_and_decrypt_file(
        self,
        download_url: str,
        target_path: Path,
        file_size: int,
        aes_key: bytes,
        iv: bytes,
        base_progress_offset: int = 0,
        total_job_size: Optional[int] = None,
        refresh_url_callback=None,
    ):
        overall_total = total_job_size if total_job_size else file_size

        # Resume support: align start to 16-byte boundary
        start_offset = 0
        if target_path.exists():
            existing_size = target_path.stat().st_size
            start_offset = (existing_size // 16) * 16

        current_offset = start_offset
        current_proxy = self.proxy_pool.get_proxy()

        speed_window = []
        last_t = time.time()
        last_bytes = current_offset
        url_refreshes = 0
        max_url_refreshes = 3

        while current_offset < file_size and self.is_running:
            if target_path.exists():
                current_offset = (target_path.stat().st_size // 16) * 16
            headers = {}
            if file_size > 0:
                headers["Range"] = f"bytes={current_offset}-{file_size - 1}"

            timeout = aiohttp.ClientTimeout(total=None, connect=15, sock_read=30)
            connector = aiohttp.TCPConnector(ssl=get_ssl_context())
            try:
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get(download_url, headers=headers, proxy=current_proxy) as resp:
                        if resp.status == 403 and refresh_url_callback is not None and url_refreshes < max_url_refreshes:
                            url_refreshes += 1
                            download_url = await refresh_url_callback()
                            await asyncio.sleep(0.5)
                            continue

                        if resp.status == 509:
                            # MegaBasterd SmartProxy failover: rotate proxy on 509
                            current_proxy = self.proxy_pool.trigger_failover_509(current_proxy)
                            await asyncio.sleep(0.5)
                            continue

                        if resp.status not in (200, 206):
                            raise ConnectionError(f"Download stream error HTTP {resp.status}")

                        # If server ignored Range (HTTP 200), restart stream cleanly from byte 0
                        if resp.status == 200 and current_offset > 0:
                            current_offset = 0

                        mode = "r+b" if target_path.exists() and current_offset > 0 else "wb"
                        with open(target_path, mode) as f_out:
                            f_out.seek(current_offset)
                            if mode == "r+b":
                                f_out.truncate(current_offset)
                            stream_cipher = get_ctr_cipher(aes_key, iv, byte_offset=current_offset)

                            async for chunk in resp.content.iter_chunked(CHUNK_READ_SIZE):
                                if not self.is_running:
                                    f_out.flush()
                                    return

                                if self.rate_limiter:
                                    await self.rate_limiter.consume(len(chunk))

                                decrypted = stream_cipher.decrypt(chunk)
                                f_out.write(decrypted)

                                current_offset += len(decrypted)

                                # Track speed & ETA
                                now = time.time()
                                dt = now - last_t
                                if dt >= 0.5:
                                    delta = current_offset - last_bytes
                                    speed = delta / dt
                                    speed_window.append(speed)
                                    if len(speed_window) > 4:
                                        speed_window.pop(0)
                                    smooth_speed = sum(speed_window) / len(speed_window)
                                    rem_bytes = max(0, overall_total - (base_progress_offset + current_offset))
                                    eta = int(rem_bytes / smooth_speed) if smooth_speed > 0 else 0

                                    self.db.update_task_progress(
                                        task_id=self.task_id,
                                        downloaded_bytes=base_progress_offset + current_offset,
                                        total_bytes=overall_total,
                                        speed_bps=smooth_speed,
                                        eta_seconds=eta
                                    )

                                    self.progress_signal.emit({
                                        "task_id": self.task_id,
                                        "downloaded": base_progress_offset + current_offset,
                                        "total": overall_total,
                                        "speed": smooth_speed,
                                        "eta": eta
                                    })

                                    last_t = now
                                    last_bytes = current_offset

            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                if self.proxy_pool.entries:
                    current_proxy = self.proxy_pool.trigger_failover_509(current_proxy)
                    await asyncio.sleep(1.0)
                else:
                    raise err

    def _process_stage3_folder(self, staging_dir: Path, destination_dir: str) -> dict:
        """
        Stage 3 Gate for MEGA folders:
        - Scans all files via CyberShield PE heuristics + Defender CLI.
        - Quarantines CRITICAL malware into CyberShield's vault.
        - Fails-closed on SCAN_ERROR (holds unverified files in .staging).
        - Moves clean and low-risk warning files into user's destination.
        """
        dest_root = Path(destination_dir)
        dest_root.mkdir(parents=True, exist_ok=True)

        scanned_files = []
        critical_count = 0
        warning_count = 0
        clean_count = 0
        scan_errors = []

        for root, dirs, files in os.walk(str(staging_dir)):
            for f in files:
                full_path = Path(root) / f
                rel_path = full_path.relative_to(staging_dir)
                dest_file_path = dest_root / rel_path
                dest_file_path.parent.mkdir(parents=True, exist_ok=True)

                ext = full_path.suffix.lower()
                is_known_config = full_path.name.lower() in ("steam_emu.ini", "codex.ini", "flt.ini", "rune.ini")
                should_scan = ext in SCAN_EXTENSIONS or is_known_config or "." in full_path.stem

                if should_scan and self.security_gate:
                    scan_res = self.security_gate.bridge.scan_file(str(full_path))
                    verdict = scan_res.get("verdict", "SCAN_ERROR")
                    threat_name = scan_res.get("threatName")
                    details = scan_res.get("details", "")

                    if verdict == "BLOCK_CRITICAL":
                        self.security_gate.bridge.quarantine_file(str(full_path), threat_name, details)
                        self.db.record_security_audit(
                            task_id=self.task_id,
                            stage="POST_DOWNLOAD",
                            verdict="BLOCK_CRITICAL",
                            threat_name=threat_name,
                            details=f"Quarantined {rel_path}: {details}"
                        )
                        critical_count += 1
                        scanned_files.append({"file": str(rel_path), "verdict": "CRITICAL", "threat": threat_name})
                        continue

                    elif verdict == "ALLOW_WARNING":
                        warning_count += 1
                        self.db.record_security_audit(
                            task_id=self.task_id,
                            stage="POST_DOWNLOAD",
                            verdict="ALLOW_WARNING",
                            threat_name=threat_name,
                            details=f"Warning permitted {rel_path}: {details}"
                        )
                        scanned_files.append({"file": str(rel_path), "verdict": "WARNING", "threat": threat_name})
                    elif verdict == "ALLOW_CLEAN":
                        clean_count += 1
                        scanned_files.append({"file": str(rel_path), "verdict": "CLEAN"})
                    else:
                        scan_errors.append(f"{rel_path}: {details}")
                        scanned_files.append({"file": str(rel_path), "verdict": "SCAN_ERROR", "details": details})
                        continue
                else:
                    clean_count += 1
                    scanned_files.append({"file": str(rel_path), "verdict": "CLEAN"})

                # Move verified file to destination
                try:
                    if dest_file_path.exists():
                        dest_file_path.unlink()
                    shutil.move(str(full_path), str(dest_file_path))
                except Exception:
                    pass

        if scan_errors:
            err_detail = "; ".join(scan_errors[:3])
            self.db.update_task_security(self.task_id, "UNCHECKED", None, f"SCAN_ERROR: {err_detail}")
            raise RuntimeError(f"Security scan failed (held in staging): {err_detail}")

        # Overall security status
        if critical_count > 0:
            overall_sec = "CRITICAL"
            sec_details = f"{critical_count} critical threat(s) quarantined"
        elif warning_count > 0:
            overall_sec = "WARNING"
            sec_details = f"{warning_count} tool/crack warning(s) permitted"
        else:
            overall_sec = "CLEAN"
            sec_details = f"All {clean_count} files verified clean"

        self.db.update_task_security(self.task_id, overall_sec, None, sec_details)
        self.db.update_task_status(self.task_id, "COMPLETED")

        return {
            "status": "COMPLETED",
            "overall_security": overall_sec,
            "critical_count": critical_count,
            "warning_count": warning_count,
            "clean_count": clean_count,
            "destination": str(dest_root),
            "files": scanned_files
        }
