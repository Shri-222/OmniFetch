"""
OmniFetch Central Engine Coordinator
Manages download task queues, thread workers, pause/resume, and CyberShield dispatching
across both HTTP/HTTPS multi-segment and BitTorrent / Magnet engines.
"""

import os
import shutil
import uuid
import time
import json
import asyncio
import threading
from pathlib import Path
from PySide6.QtCore import QObject, Signal, Qt
import libtorrent as lt

from .config import Config
from .db import Database, extract_info_hash
from .staging import StagingManager
from .security_gate import SecurityGate
from .archive_extractor import SafeArchiveExtractor, is_supported_archive
from ..engines.http.downloader import HttpDownloader, parse_url_expiry
from ..engines.http.hls_remuxer import HlsRemuxWorker, is_hls_url
from ..engines.http.worker import HttpDownloadWorker
from ..engines.torrent.session import TorrentSessionManager, _get_ih_hex
from ..engines.torrent.worker import TorrentDownloadWorker
from ..engines.mega.proxy_pool import ProxyPool
from ..engines.mega.worker import MegaDownloadWorker
from .logger import get_logger

logger = get_logger("engine_manager")

_FILE_CATEGORY_EXTS = {
    "Videos": {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".flv", ".ts", ".m3u8"},
    "Archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz", ".iso"},
    "Programs": {".exe", ".msi", ".bat", ".cmd", ".ps1", ".apk", ".dmg", ".deb", ".rpm"},
    "Documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".epub", ".md"},
    "Images": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".avif", ".tiff"},
}


def classify_file_category(filename: str | None, engine_type: str = "HTTP") -> str | None:
    ext = Path(str(filename or "")).suffix.lower()
    for cat, exts in _FILE_CATEGORY_EXTS.items():
        if ext in exts:
            return cat
    return None


class EngineManager(QObject):
    task_added = Signal(str)
    tasks_changed = Signal()
    task_progress = Signal(dict)
    task_status_changed = Signal(str, str)
    task_completed = Signal(str, dict)
    task_failed = Signal(str, str)

    def __init__(self, config: Config = None, db: Database = None):
        super().__init__()
        self.config = config or Config()
        self.db = db or Database()
        self.staging = StagingManager(self.config.staging_dir)
        self.security_gate = SecurityGate(
            cybershield_root=self.config.cybershield_root,
            db=self.db,
            staging_manager=self.staging
        )
        self.http_downloader = HttpDownloader(
            db=self.db,
            staging_manager=self.staging,
            security_gate=self.security_gate if self.config.cybershield_enabled else None,
            speed_limit_kbs=self.config.speed_limit_kbs
        )
        self.torrent_session = TorrentSessionManager.get_instance(self.config.staging_dir)
        self.torrent_session.apply_settings(self.config)
        if self.config.speed_limit_kbs > 0:
            self.torrent_session.set_speed_limit(self.config.speed_limit_kbs)
        self.proxy_pool = ProxyPool(passive_mode=bool(getattr(self.config, "proxy_passive_mode", True)))
        if getattr(self.config, "proxies", None):
            self.proxy_pool.load_proxies(self.config.proxies)
        self.active_workers = {}  # task_id -> worker
        self.torrent_sources = {}  # task_id -> source metadata dict
        self._pending_queue = []   # FIFO task_ids waiting on max_concurrent_tasks slot
        self._queue_lock = threading.RLock()
        self.recover_on_startup()

    def recover_on_startup(self):
        """
        Cold-restart recovery executed on EngineManager initialization:
        1) Reconciles stale DOWNLOADING/QUEUED rows from prior crash/exit -> PAUSED (speed=0, eta=0).
        2) Backfills migrated TORRENT/MEGA rows with resumable == -1 -> 1.
        3) Rehydrates persisted TORRENT handles cleanly in paused state using resume.dat + meta.torrent.
        4) Preserves STAGED/SCANNING tasks so Resume runs Stage 3 scan directly without re-downloading.
        """
        try:
            tasks = self.db.get_all_tasks()
        except Exception as exc:
            logger.warning(f"recover_on_startup skipped (DB read error): {exc}")
            return

        for t in tasks:
            tid = t["id"]
            st = t.get("status")
            eng = t.get("engine_type", "HTTP")

            if st in ("DOWNLOADING", "QUEUED"):
                self.db.update_task_status(tid, "PAUSED")
                st = "PAUSED"

            if eng in ("TORRENT", "MEGA") and t.get("resumable", -1) == -1:
                self.db.update_task_resumable(tid, 1)

            if eng == "TORRENT" and st in ("PAUSED", "FAILED"):
                t_path = t.get("torrent_path")
                if not t_path:
                    cand = Path(t["staging_path"]) / "meta.torrent"
                    if cand.exists():
                        t_path = str(cand)
                        self.db.update_task_fields(tid, torrent_path=t_path)

                self.torrent_sources[tid] = {
                    "source": t_path if (t_path and os.path.exists(t_path)) else t.get("url"),
                    "priorities": t.get("file_priorities"),
                    "sequential": bool(t.get("sequential", 0)),
                    "stop_ratio": t.get("stop_ratio") if t.get("stop_ratio") is not None else float(self.config.seeding_ratio_cutoff or 0.0),
                    "torrent_path": t_path,
                    "info_hash": t.get("info_hash"),
                }

                # Rehydrate paused torrent handle cleanly when metadata or resume.dat exists
                resume_exists = (Path(t["staging_path"]) / "resume.dat").exists()
                meta_exists = bool(t_path and os.path.exists(t_path))
                raw_url = t.get("url") or ""
                if st == "PAUSED" and (resume_exists or meta_exists or raw_url.lower().startswith("magnet:")):
                    try:
                        self.torrent_session.add_active_torrent(
                            task_id=tid,
                            source=self.torrent_sources[tid]["source"],
                            staging_path=t["staging_path"],
                            file_priorities=t.get("file_priorities"),
                            sequential=bool(t.get("sequential", 0)),
                            torrent_path=t_path,
                            info_hash=t.get("info_hash"),
                            start_paused=True,
                        )
                    except Exception as exc:
                        logger.debug(f"Torrent handle rehydration deferred for {tid}: {exc}")

        try:
            gc_res = self.clean_orphaned_staging(min_age_seconds=3600)
            if gc_res.get("removed_count", 0) > 0:
                logger.info(
                    f"Startup orphan staging GC reclaimed {gc_res['reclaimed_mb']} MB "
                    f"across {gc_res['removed_count']} stale directories."
                )
        except Exception as exc:
            logger.debug(f"Startup orphan staging GC skipped: {exc}")

    def clean_orphaned_staging(self, min_age_seconds: int = 3600) -> dict:
        """Removes stale .staging subdirectories missing from DB active/history tasks and _metadata_cache."""
        active_ids = {t["id"] for t in self.db.get_all_tasks()} | set(self.active_workers.keys())
        return self.staging.cleanup_orphaned_staging(active_ids, min_age_seconds=min_age_seconds)

    def apply_torrent_settings(self) -> dict:
        return self.torrent_session.apply_settings(self.config)

    def all_tasks_terminal(self) -> bool:
        """Returns True when zero workers are running and no tasks remain active/queued."""
        with self._queue_lock:
            if any(w.isRunning() for w in self.active_workers.values()):
                return False
            if self._pending_queue:
                return False
        for t in self.db.get_all_tasks():
            if t.get("status") in ("DOWNLOADING", "QUEUED", "STAGED", "SCANNING"):
                return False
        return True

    def check_disk_space(self, dest_dir: str, required_bytes: int, reserve_bytes: int = 50 * 1024 * 1024) -> dict:
        """
        Verifies free disk space on the destination volume.
        Warns if required_bytes + reserve_bytes exceeds free space when required_bytes > 0.
        """
        target = Path(dest_dir or self.config.download_dir)
        probe_path = target
        while not probe_path.exists() and probe_path.parent != probe_path:
            probe_path = probe_path.parent
        try:
            usage = shutil.disk_usage(str(probe_path))
            free_bytes = int(usage.free)
        except Exception:
            free_bytes = -1

        if required_bytes <= 0 or free_bytes < 0:
            return {"ok": True, "free_bytes": max(0, free_bytes), "required_bytes": required_bytes, "needed_with_reserve": required_bytes, "message": ""}

        needed = int(required_bytes) + int(reserve_bytes)
        ok = free_bytes >= needed
        msg = ""
        if not ok:
            req_mb = round(required_bytes / (1024 * 1024), 1)
            free_mb = round(free_bytes / (1024 * 1024), 1)
            msg = f"Insufficient disk space: file needs {req_mb} MB (+50 MB reserve), only {free_mb} MB free on {probe_path}."
        return {
            "ok": ok,
            "free_bytes": free_bytes,
            "required_bytes": int(required_bytes),
            "needed_with_reserve": needed,
            "message": msg,
        }

    def categorize_destination(self, base_dest: str, filename: str | None, engine_type: str = "HTTP") -> str:
        """Routes destination into <save_dir>/<Category> when auto_categorize_folders is enabled."""
        if not getattr(self.config, "auto_categorize_folders", False):
            return base_dest
        cat = classify_file_category(filename, engine_type=engine_type)
        if not cat:
            return base_dest
        base_p = Path(base_dest)
        if base_p.name == cat:
            return base_dest
        sub = base_p / cat
        sub.mkdir(parents=True, exist_ok=True)
        return str(sub)

    @property
    def rate_limiter(self):
        return self.http_downloader.rate_limiter

    def set_global_speed_limit(self, speed_kbs: int):
        self.config.speed_limit_kbs = speed_kbs
        self.config.save()
        self.http_downloader.rate_limiter.set_rate(speed_kbs)
        self.torrent_session.set_speed_limit(speed_kbs)

    async def probe_url(self, url):
        return await self.http_downloader.probe(url)

    def fetch_magnet_metadata(self, magnet_uri, timeout_seconds=60, cancel_check=None, status_callback=None):
        return self.torrent_session.fetch_magnet_metadata(
            magnet_uri,
            timeout_seconds=timeout_seconds,
            cancel_check=cancel_check,
            status_callback=status_callback,
        )

    def load_torrent_file(self, torrent_path):
        return self.torrent_session.load_torrent_file(torrent_path)

    def add_download(self, url, filename=None, destination=None, num_segments=None, engine_type="HTTP", custom_headers=None, resumable=-1):
        ih = extract_info_hash(url) if engine_type == "TORRENT" else None
        dup = self.db.find_duplicate_task(url=url, info_hash=ih)
        if dup:
            if engine_type == "TORRENT" and isinstance(url, str) and url.lower().startswith("magnet:"):
                self.torrent_session.merge_trackers(dup["id"], url)
            logger.info(f"Duplicate {engine_type} URL detected -> reusing existing Task #{dup['id']}")
            return dup["id"]

        task_id = str(uuid.uuid4())[:8]
        base_dest = destination or self.config.download_dir
        dest_dir = self.categorize_destination(base_dest, filename, engine_type=engine_type)
        staging_dir = self.staging.allocate_task_staging(task_id)

        # Stage 1 Pre-Download Check
        sec_eval = self.security_gate.evaluate_pre_download(url, filename or "download.bin")
        init_security = "CRITICAL" if sec_eval.get("severity") == "CRITICAL" or sec_eval.get("verdict") == "BLOCK_CRITICAL" else "UNCHECKED"

        if engine_type in ("TORRENT", "MEGA"):
            resumable = 1

        origin_ref = None
        if isinstance(custom_headers, dict):
            origin_ref = custom_headers.get("Referer") or custom_headers.get("referer")
        expires_at = parse_url_expiry(url) if engine_type == "HTTP" else None

        task_data = {
            "id": task_id,
            "url": url,
            "filename": filename or "download.bin",
            "destination": dest_dir,
            "staging_path": str(staging_dir),
            "engine_type": engine_type,
            "status": "QUEUED",
            "total_bytes": 0,
            "downloaded_bytes": 0,
            "speed_bps": 0.0,
            "eta_seconds": 0,
            "num_segments": num_segments or self.config.max_segments_per_task,
            "security_status": init_security,
            "threat_name": sec_eval.get("threat_name"),
            "threat_details": sec_eval.get("details"),
            "custom_headers": custom_headers,
            "resumable": resumable,
            "info_hash": ih,
            "origin_referer": origin_ref,
            "expires_at": expires_at,
            "created_at": time.time()
        }

        self.db.add_task(task_data)
        self.task_added.emit(task_id)
        self.tasks_changed.emit()
        return task_id

    def add_torrent_download(self, source, name, destination, file_priorities=None, sequential=False, stop_ratio=None, magnet_uri=None):
        if stop_ratio is None:
            stop_ratio = float(self.config.seeding_ratio_cutoff or 0.0)
        ih_hex = _get_ih_hex(source) or extract_info_hash(magnet_uri)
        dup_url = magnet_uri or (source if isinstance(source, str) else None)
        dup = self.db.find_duplicate_task(url=dup_url, info_hash=ih_hex)
        if dup:
            if magnet_uri:
                self.torrent_session.merge_trackers(dup["id"], magnet_uri)
            elif isinstance(source, str) and source.lower().startswith("magnet:"):
                self.torrent_session.merge_trackers(dup["id"], source)
            logger.info(f"Duplicate torrent info_hash={ih_hex} -> reusing existing Task #{dup['id']}")
            return dup["id"]

        task_id = str(uuid.uuid4())[:8]
        dest_dir = destination or self.config.download_dir
        staging_dir = self.staging.allocate_task_staging(task_id)

        # Persist resolved metadata immediately to .staging/<task_id>/meta.torrent
        meta_path = staging_dir / "meta.torrent"
        saved_meta_path = None
        if isinstance(source, lt.torrent_info):
            extra_tr = None
            if magnet_uri:
                try:
                    extra_tr = list(lt.parse_magnet_uri(magnet_uri).trackers)
                except Exception:
                    extra_tr = None
            saved_meta_path = self.torrent_session.save_torrent_metadata(source, meta_path, extra_trackers=extra_tr)
        elif isinstance(source, str) and os.path.exists(source):
            try:
                ti = self.torrent_session.load_torrent_file(source)
                ih_hex = ih_hex or _get_ih_hex(ti)
                saved_meta_path = self.torrent_session.save_torrent_metadata(ti, meta_path)
            except Exception:
                saved_meta_path = None

        torrent_path_str = str(saved_meta_path) if saved_meta_path else None
        if magnet_uri:
            url_repr = magnet_uri
        elif isinstance(source, str):
            url_repr = source
        elif ih_hex:
            url_repr = f"magnet:?xt=urn:btih:{ih_hex}"
        else:
            url_repr = f"torrent:{name}"

        self.torrent_sources[task_id] = {
            "source": source,
            "priorities": file_priorities,
            "sequential": sequential,
            "stop_ratio": stop_ratio,
            "torrent_path": torrent_path_str,
            "info_hash": ih_hex,
        }

        task_data = {
            "id": task_id,
            "url": url_repr,
            "filename": name,
            "destination": dest_dir,
            "staging_path": str(staging_dir),
            "engine_type": "TORRENT",
            "status": "QUEUED",
            "total_bytes": 0,
            "downloaded_bytes": 0,
            "speed_bps": 0.0,
            "eta_seconds": 0,
            "num_segments": 1,
            "security_status": "UNCHECKED",
            "threat_name": None,
            "threat_details": None,
            "resumable": 1,
            "info_hash": ih_hex,
            "torrent_path": torrent_path_str,
            "file_priorities": file_priorities,
            "sequential": 1 if sequential else 0,
            "stop_ratio": stop_ratio,
            "created_at": time.time()
        }

        self.db.add_task(task_data)
        self.task_added.emit(task_id)
        self.tasks_changed.emit()
        self.start_download(task_id)

        return task_id

    def add_mega_download(self, url, filename=None, destination=None, selected_indices=None):
        dup = self.db.find_duplicate_task(url=url)
        if dup:
            logger.info(f"Duplicate MEGA URL detected -> reusing existing Task #{dup['id']}")
            return dup["id"]

        task_id = str(uuid.uuid4())[:8]
        dest_dir = self.categorize_destination(destination or self.config.download_dir, filename, engine_type="MEGA")
        staging_dir = self.staging.allocate_task_staging(task_id)

        sec_eval = self.security_gate.evaluate_pre_download(url, filename or "MEGA_Download")
        init_security = "CRITICAL" if sec_eval.get("severity") == "CRITICAL" or sec_eval.get("verdict") == "BLOCK_CRITICAL" else "UNCHECKED"

        task_data = {
            "id": task_id,
            "url": url,
            "filename": filename or "MEGA_Download",
            "destination": dest_dir,
            "staging_path": str(staging_dir),
            "engine_type": "MEGA",
            "status": "QUEUED",
            "total_bytes": 0,
            "downloaded_bytes": 0,
            "speed_bps": 0.0,
            "eta_seconds": 0,
            "num_segments": 1,
            "security_status": init_security,
            "threat_name": sec_eval.get("threat_name"),
            "threat_details": sec_eval.get("details"),
            "resumable": 1,
            "selected_indices": selected_indices,
            "created_at": time.time()
        }

        self.db.add_task(task_data)
        self.task_added.emit(task_id)
        self.tasks_changed.emit()

        if init_security == "CRITICAL":
            block_msg = f"Blocked by Stage 1 CyberShield Gate: {sec_eval.get('threat_name') or 'Critical Threat'}"
            self.db.update_task_status(task_id, "FAILED", error_message=block_msg)
            self.task_failed.emit(task_id, block_msg)
            self.tasks_changed.emit()
            return task_id

        self.start_download(task_id)

        return task_id

    def _wire_and_start_worker(self, task_id, worker):
        worker.progress_signal.connect(self._on_worker_progress)
        worker.status_signal.connect(self._on_worker_status)
        worker.finished_signal.connect(self._on_worker_finished)
        worker.error_signal.connect(self._on_worker_error)
        # DirectConnection ensures headless CLI/pytest queues advance even without an active Qt event loop
        worker.finished.connect(
            lambda tid=task_id, w=worker: self._on_worker_thread_finished(tid, w),
            Qt.DirectConnection,
        )
        self.active_workers[task_id] = worker
        worker.start()

    def _on_worker_thread_finished(self, task_id, worker):
        with self._queue_lock:
            if self.active_workers.get(task_id) is worker:
                del self.active_workers[task_id]
        self._schedule_next_queued()

    def _schedule_next_queued(self):
        with self._queue_lock:
            max_conc = max(1, int(getattr(self.config, "max_concurrent_tasks", 4) or 4))
            while self._pending_queue and len(self.active_workers) < max_conc:
                next_id = self._pending_queue.pop(0)
                task = self.db.get_task(next_id)
                if not task:
                    continue
                if task.get("status") != "QUEUED":
                    continue
                if next_id in self.active_workers:
                    continue
                self._launch_task_worker(task)

    def _build_worker_for_task(self, task):
        task_id = task["id"]
        engine = task.get("engine_type", "HTTP")

        if engine == "TORRENT":
            meta = self.torrent_sources.get(task_id, {})
            t_path = meta.get("torrent_path") or task.get("torrent_path")
            if not t_path:
                cand = Path(task["staging_path"]) / "meta.torrent"
                if cand.exists():
                    t_path = str(cand)
            source = meta.get("source")
            if source is None:
                source = t_path if (t_path and os.path.exists(t_path)) else task["url"]
            file_priorities = meta.get("priorities")
            if file_priorities is None:
                file_priorities = task.get("file_priorities")
            sequential = meta["sequential"] if "sequential" in meta else bool(task.get("sequential", 0))
            stop_ratio = meta["stop_ratio"] if "stop_ratio" in meta else (
                task.get("stop_ratio") if task.get("stop_ratio") is not None else float(self.config.seeding_ratio_cutoff or 0.0)
            )
            ih = meta.get("info_hash") or task.get("info_hash")

            return TorrentDownloadWorker(
                task_id=task_id,
                db=self.db,
                staging_manager=self.staging,
                security_gate=self.security_gate,
                source=source,
                file_priorities=file_priorities,
                sequential=sequential,
                stop_ratio=stop_ratio,
                torrent_path=t_path,
                info_hash=ih,
                session_mgr=self.torrent_session,
            )
        elif engine == "MEGA":
            return MegaDownloadWorker(
                task_id=task_id,
                db=self.db,
                staging_manager=self.staging,
                security_gate=self.security_gate,
                url=task["url"],
                destination_dir=task["destination"],
                proxy_pool=self.proxy_pool,
                selected_file_indices=task.get("selected_indices"),
                rate_limiter=self.http_downloader.rate_limiter,
            )
        else:
            if is_hls_url(task.get("url", "")):
                return HlsRemuxWorker(
                    task_id,
                    self.db,
                    self.staging,
                    self.security_gate if self.config.cybershield_enabled else None,
                )
            return HttpDownloadWorker(task_id, self.http_downloader)

    def _launch_task_worker(self, task):
        worker = self._build_worker_for_task(task)
        self._wire_and_start_worker(task["id"], worker)

    def force_start_task(self, task_id: str) -> bool:
        """Starts a QUEUED or PAUSED task immediately even when max_concurrent_tasks is reached."""
        with self._queue_lock:
            task = self.db.get_task(task_id)
            if not task:
                return False
            if task.get("status") == "COMPLETED":
                return False
            if task.get("security_status") == "CRITICAL":
                return False
            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)
            existing = self.active_workers.get(task_id)
            if existing and existing.isRunning():
                return True
            if task.get("engine_type") == "TORRENT":
                self.torrent_session.resume_torrent(task_id)
            if task.get("status") not in ("STAGED", "SCANNING"):
                self.db.update_task_status(task_id, "QUEUED", error_message=None)
                self.task_status_changed.emit(task_id, "QUEUED")
            self._launch_task_worker(task)
        self.tasks_changed.emit()
        return True

    def move_to_top(self, task_id: str) -> bool:
        """Moves a QUEUED task to index 0 of the FIFO pending queue."""
        with self._queue_lock:
            task = self.db.get_task(task_id)
            if not task or task.get("status") != "QUEUED":
                return False
            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)
            self._pending_queue.insert(0, task_id)
        self.tasks_changed.emit()
        return True

    def start_download(self, task_id):
        with self._queue_lock:
            existing = self.active_workers.get(task_id)
            if existing is not None:
                is_cancelling = (
                    getattr(existing, "cancel_token", {}).get("is_cancelled", False) or
                    not getattr(existing, "is_running", True)
                )
                if existing.isRunning() and not is_cancelling:
                    return  # Truly running and not pausing
                if existing.isRunning():
                    existing.wait(3000)
                if self.active_workers.get(task_id) is existing:
                    del self.active_workers[task_id]

            task = self.db.get_task(task_id)
            if not task:
                return

            # Enforce Stage 1 CRITICAL block across every entrypoint (Browser, Clipboard, CLI)
            if task.get("security_status") == "CRITICAL":
                block_msg = f"Blocked by Stage 1 CyberShield Gate: {task.get('threat_name') or task.get('threat_details') or 'Critical Threat'}"
                self.db.update_task_status(task_id, "FAILED", error_message=block_msg)
                self.task_failed.emit(task_id, block_msg)
                return

            # Preserve STAGED/SCANNING status when recovering Stage 3 scan directly
            if task.get("status") not in ("STAGED", "SCANNING"):
                self.db.update_task_status(task_id, "QUEUED", error_message=None)
                self.task_status_changed.emit(task_id, "QUEUED")

            max_conc = max(1, int(getattr(self.config, "max_concurrent_tasks", 4) or 4))
            if task.get("status") not in ("STAGED", "SCANNING") and len(self.active_workers) >= max_conc:
                if task_id not in self._pending_queue:
                    self._pending_queue.append(task_id)
                return

            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)

            self._launch_task_worker(task)

    def refresh_download_address(self, task_id: str, new_url: str, custom_headers: dict = None, force: bool = False) -> dict:
        """
        Replaces an expired/broken HTTP task URL + headers while preserving all partial
        .staging/<task_id>/ bytes and SQLite segments intact, validates compatibility
        (Content-Length / ETag), and resets status to PAUSED ready for resume.
        """
        task = self.db.get_task(task_id)
        if not task:
            return {"success": False, "compatible": False, "reason": "Task not found"}

        clean_url = (new_url or "").strip()
        if not clean_url.lower().startswith(("http://", "https://")):
            return {"success": False, "compatible": False, "reason": "URL must start with http:// or https://"}

        existing_headers = task.get("custom_headers") or {}
        if isinstance(existing_headers, str):
            try:
                existing_headers = json.loads(existing_headers)
            except Exception:
                existing_headers = {}
        merged_headers = dict(existing_headers) if isinstance(existing_headers, dict) else {}
        if custom_headers:
            for k, v in custom_headers.items():
                if v is not None and v != "":
                    merged_headers[k] = v

        probe_res = asyncio.run(
            self.http_downloader.probe(clean_url, custom_headers=merged_headers, caller_filename=task.get("filename"))
        )
        p_status = probe_res.get("status", 0)
        if p_status >= 400 or (p_status == 0 and probe_res.get("error")):
            return {
                "success": False,
                "compatible": False,
                "reason": f"Fresh URL check failed: {probe_res.get('error') or f'HTTP {p_status}'}",
                "probe": probe_res,
            }

        old_total = task.get("total_bytes") or 0
        new_total = probe_res.get("total_bytes") or 0
        old_etag = (task.get("etag") or "").strip()
        new_etag = (probe_res.get("etag") or "").strip()

        if not force and old_total > 0 and new_total > 0 and new_total != old_total:
            return {
                "success": False,
                "compatible": False,
                "reason": f"Content-Length mismatch (expected {old_total} B, got {new_total} B)",
                "probe": probe_res,
            }

        if not force and old_etag and new_etag and old_etag != new_etag:
            return {
                "success": False,
                "compatible": False,
                "reason": f"ETag mismatch ({new_etag} != {old_etag})",
                "probe": probe_res,
            }

        if probe_res.get("effective_user_agent") and "User-Agent" not in merged_headers:
            merged_headers["User-Agent"] = probe_res["effective_user_agent"]

        updates = {
            "url": clean_url,
            "custom_headers": merged_headers or None,
            "final_url": probe_res.get("final_url") or clean_url,
            "expires_at": probe_res.get("expires_at") or parse_url_expiry(clean_url),
            "etag": new_etag or old_etag or None,
            "last_modified": probe_res.get("last_modified") or task.get("last_modified"),
            "error_message": None,
        }
        if merged_headers.get("Referer"):
            updates["origin_referer"] = merged_headers["Referer"]
        if probe_res.get("accept_ranges"):
            updates["resumable"] = 1

        self.db.update_task_fields(task_id, **updates)
        self.db.update_task_status(task_id, "PAUSED", error_message=None)
        self.task_status_changed.emit(task_id, "PAUSED")
        return {"success": True, "compatible": True, "probe": probe_res}

    def pause_download(self, task_id):
        with self._queue_lock:
            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)
                self.db.update_task_status(task_id, "PAUSED")
                self.task_status_changed.emit(task_id, "PAUSED")
                return
            worker = self.active_workers.get(task_id)
        if worker is not None:
            if hasattr(worker, "pause"):
                worker.pause()
            elif hasattr(worker, "stop"):
                worker.stop()
            if worker.isRunning():
                worker.wait(2500)
            with self._queue_lock:
                if not worker.isRunning() and self.active_workers.get(task_id) is worker:
                    del self.active_workers[task_id]
            self._schedule_next_queued()
        else:
            task = self.db.get_task(task_id)
            if task and task.get("engine_type") == "TORRENT":
                self.torrent_session.pause_torrent(task_id, task.get("staging_path"))
                self.db.update_task_status(task_id, "PAUSED")
                self.task_status_changed.emit(task_id, "PAUSED")

    def resume_download(self, task_id):
        task = self.db.get_task(task_id)
        if not task:
            return
        if task.get("status") == "COMPLETED":
            return
        if task.get("security_status") == "CRITICAL":
            block_msg = f"Blocked by Stage 1 CyberShield Gate: {task.get('threat_name') or 'Critical Threat'}"
            self.db.update_task_status(task_id, "FAILED", error_message=block_msg)
            self.task_failed.emit(task_id, block_msg)
            return
        if task.get("engine_type") == "TORRENT":
            self.torrent_session.resume_torrent(task_id)
        self.start_download(task_id)

    def pause_all(self):
        with self._queue_lock:
            for q_id in list(self._pending_queue):
                self.db.update_task_status(q_id, "PAUSED")
                self.task_status_changed.emit(q_id, "PAUSED")
            self._pending_queue.clear()
            active_ids = list(self.active_workers.keys())
        for task_id in active_ids:
            self.pause_download(task_id)

    def resume_all(self):
        tasks = self.db.get_all_tasks()
        for t in tasks:
            if t.get("status") in ("PAUSED", "QUEUED", "STAGED", "SCANNING"):
                self.start_download(t["id"])

    def shutdown(self):
        self.pause_all()
        for worker in list(self.active_workers.values()):
            if hasattr(worker, "wait") and worker.isRunning():
                worker.wait(2500)
        self.torrent_session.flush_all_sessions(timeout=5.0)
        TorrentSessionManager.reset_instance(self.torrent_session)
        self.db.close()

    def cancel_download(self, task_id):
        with self._queue_lock:
            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)
        if task_id in self.active_workers:
            worker = self.active_workers[task_id]
            if hasattr(worker, 'cancel'):
                worker.cancel()
            elif hasattr(worker, 'stop'):
                worker.stop()
        self.db.update_task_status(task_id, "PAUSED")
        self._schedule_next_queued()

    def delete_task(self, task_id, delete_files=False):
        task = self.db.get_task(task_id)
        with self._queue_lock:
            if task_id in self._pending_queue:
                self._pending_queue.remove(task_id)
        if not task or task.get("status") != "COMPLETED" or task_id in self.active_workers:
            self.cancel_download(task_id)
        if task_id in self.active_workers:
            try:
                self.active_workers[task_id].wait(1500)
            except Exception:
                pass
            with self._queue_lock:
                if task_id in self.active_workers:
                    del self.active_workers[task_id]

        if task_id in self.torrent_session.active_handles:
            self.torrent_session.remove_torrent(task_id, delete_files=True)

        # Always clean orphaned .staging/<task_id>/ when deleting a task
        self.staging.cleanup_task(task_id)

        # Only remove final completed payload from user destination when explicitly requested
        if delete_files and task and task.get("status") == "COMPLETED":
            dest_p = Path(task.get("destination") or "")
            fn = task.get("filename") or ""
            if dest_p and fn:
                target = dest_p / fn
                try:
                    if target.is_file():
                        target.unlink()
                    elif target.is_dir():
                        shutil.rmtree(str(target), ignore_errors=True)
                except Exception:
                    pass

        self.db.delete_task(task_id)
        self._schedule_next_queued()
        if task_id in self.torrent_sources:
            del self.torrent_sources[task_id]
        self.tasks_changed.emit()

    def _on_worker_progress(self, progress_dict):
        self.task_progress.emit(progress_dict)

    def _on_worker_status(self, task_id, status):
        self.task_status_changed.emit(task_id, status)

    def _on_worker_finished(self, task_id, result):
        if task_id in self.active_workers:
            del self.active_workers[task_id]

        res = dict(result) if isinstance(result, dict) else result

        # Optional auto-categorize relocation for generic initial filenames resolved mid-transfer
        if (
            isinstance(res, dict)
            and getattr(self.config, "auto_categorize_folders", False)
            and res.get("final_path")
            and Path(res["final_path"]).is_file()
        ):
            src_fp = Path(res["final_path"])
            task_row = self.db.get_task(task_id)
            cat_dest = self.categorize_destination(self.config.download_dir, src_fp.name, engine_type=(task_row or {}).get("engine_type", "HTTP"))
            if Path(cat_dest) != src_fp.parent:
                try:
                    new_fp = Path(cat_dest) / src_fp.name
                    if not new_fp.exists():
                        shutil.move(str(src_fp), str(new_fp))
                        res["final_path"] = str(new_fp)
                        self.db.update_task_fields(task_id, destination=cat_dest)
                except Exception as exc:
                    logger.debug(f"Task {task_id}: Auto-categorize move skipped: {exc}")

        if (
            isinstance(res, dict)
            and getattr(self.config, "auto_extract_archives", False)
            and res.get("action") == "MOVED_CLEAN"
            and res.get("final_path")
            and is_supported_archive(res["final_path"])
        ):
            try:
                extract_res = SafeArchiveExtractor.extract_and_scan(
                    res["final_path"],
                    res,
                    security_gate=self.security_gate if self.config.cybershield_enabled else None,
                    db=self.db,
                    task_id=task_id,
                )
                res["extraction"] = extract_res
            except Exception as exc:
                logger.warning(f"Task {task_id}: Safe auto-extraction blocked/failed: {exc}")
                res["extraction"] = {"extracted": False, "reason": str(exc)}

        self.task_completed.emit(task_id, res)
        self.tasks_changed.emit()

    def _on_worker_error(self, task_id, error_msg):
        logger.error(f"Task {task_id} failed with error: {error_msg}")
        if task_id in self.active_workers:
            del self.active_workers[task_id]
        self.db.update_task_status(task_id, "FAILED", error_message=str(error_msg))
        self.task_failed.emit(task_id, str(error_msg))
        self.tasks_changed.emit()
