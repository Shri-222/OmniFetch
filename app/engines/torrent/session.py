"""
OmniFetch libtorrent 2.1 Session & Fast-Resume Manager
Integrates modern libtorrent 2.1 API:
- Zero-payload magnet metadata inspection via lt.parse_magnet_uri + upload_mode (qBittorrent pattern).
- DHT bootstrap routers & fallback public trackers for fast magnet peer discovery.
- Strict staging containment (.staging/<task_id>/).
- Fast-resume data persistence (write_resume_data_buf).
- Configurable auto-stop seeding cutoff rules.
"""

import os
import time
import asyncio
import threading
import warnings
from pathlib import Path
import libtorrent as lt

from ...core.db import extract_info_hash
from ...core.logger import get_logger

logger = get_logger("torrent_session")

DHT_BOOTSTRAP_ROUTERS = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.libtorrent.org", 25401),
]

PUBLIC_FALLBACK_TRACKERS = [
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
]


def _get_ih_hex(obj) -> str:
    """Extracts a normalized lowercase hex info_hash from a handle, torrent_info, params, or URI."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return extract_info_hash(obj) or ""
    try:
        if hasattr(obj, "info_hashes"):
            ihs = obj.info_hashes()
            if ihs.has_v1():
                return str(ihs.v1).lower()
            if ihs.has_v2():
                return str(ihs.v2).lower()
            best = str(ihs.get_best()).lower()
            return "" if set(best) == {"0"} else best
        if hasattr(obj, "info_hash"):
            h = str(obj.info_hash()).lower()
            return "" if set(h) == {"0"} else h
    except Exception:
        pass
    return ""


def _atomic_write_bytes(target_path: Path, data: bytes):
    """Writes bytes atomically using a PID-scoped temp file + os.replace."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(str(tmp_path), str(target_path))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _serialize_torrent_info(ti: lt.torrent_info, extra_trackers: list | None = None) -> bytes:
    """Serializes lt.torrent_info into valid bencoded .torrent file bytes."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ct = lt.create_torrent(ti)
        if extra_trackers:
            existing = {tr.url for tr in ti.trackers()} if hasattr(ti, "trackers") else set()
            for idx, tr in enumerate(extra_trackers):
                if tr and tr not in existing:
                    try:
                        ct.add_tracker(tr, idx)
                        existing.add(tr)
                    except Exception:
                        pass
    return bytes(lt.bencode(ct.generate()))


class TorrentSessionManager:
    _instance = None

    @classmethod
    def get_instance(cls, staging_dir=None):
        if cls._instance is None:
            cls._instance = cls(staging_dir)
        return cls._instance

    @classmethod
    def reset_instance(cls, instance=None):
        """Resets the singleton reference on shutdown so fresh cold-restart sessions bind cleanly."""
        if instance is None or cls._instance is instance:
            cls._instance = None

    def __init__(self, staging_dir=None):
        self.staging_dir = Path(staging_dir) if staging_dir else Path.home() / "Downloads" / "OmniFetch" / ".staging"
        self.metadata_dir = self.staging_dir / "_metadata_cache"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        settings = {
            'user_agent': 'OmniFetch/1.0 libtorrent/' + lt.__version__,
            'listen_interfaces': '0.0.0.0:6881,[::]:6881',
            'enable_dht': True,
            'enable_lsd': True,
            'allow_multiple_connections_per_ip': True,
            'dht_bootstrap_nodes': ",".join(f"{h}:{p}" for h, p in DHT_BOOTSTRAP_ROUTERS),
            'alert_mask': (
                lt.alert.category_t.status_notification |
                lt.alert.category_t.storage_notification |
                lt.alert.category_t.error_notification
            )
        }
        self.ses = lt.session(settings)
        self.active_handles = {}  # task_id -> torrent_handle
        self._max_peers_per_torrent = 60
        self._pump_lock = threading.RLock()
        self._handle_staging = {}   # ih_hex -> Path(staging_path)
        self._resume_waiters = {}   # ih_hex -> {"event": Event, "success": bool, "error": str|None, "staging_path": Path}
        self._metadata_waiters = {} # ih_hex -> {"event": Event, "ti": lt.torrent_info|None}

    def save_torrent_metadata(self, ti: lt.torrent_info, target_path: Path, extra_trackers: list | None = None) -> Path | None:
        """Persists torrent metadata atomically to target_path and _metadata_cache/<info_hash>.torrent."""
        if ti is None:
            return None
        try:
            raw = _serialize_torrent_info(ti, extra_trackers=extra_trackers)
            _atomic_write_bytes(Path(target_path), raw)
            ih = _get_ih_hex(ti)
            if ih:
                cache_path = self.metadata_dir / f"{ih}.torrent"
                if Path(target_path) != cache_path:
                    _atomic_write_bytes(cache_path, raw)
            return Path(target_path)
        except Exception as exc:
            logger.warning(f"Failed saving torrent metadata to {target_path}: {exc}")
            return None

    def pump_alerts(self):
        """
        Centralized lock-protected alert pump.
        Routes save_resume_data_alert, save_resume_data_failed_alert, and
        metadata_received_alert strictly by info_hash so concurrent tasks never
        swallow or contaminate another task's resume.dat.
        """
        with self._pump_lock:
            alerts = self.ses.pop_alerts()
            for a in alerts:
                if isinstance(a, lt.metadata_received_alert):
                    ih = _get_ih_hex(a.handle)
                    waiter = self._metadata_waiters.get(ih)
                    if waiter and a.handle.is_valid():
                        try:
                            ti = a.handle.torrent_file()
                            if ti:
                                waiter["ti"] = lt.torrent_info(ti)
                                waiter["event"].set()
                        except Exception:
                            pass
                elif isinstance(a, lt.save_resume_data_alert):
                    ih = _get_ih_hex(a.handle) or _get_ih_hex(a.params)
                    waiter = self._resume_waiters.get(ih)
                    staging_path = (waiter.get("staging_path") if waiter else None) or self._handle_staging.get(ih)
                    if staging_path:
                        try:
                            staging_dir = Path(staging_path)
                            staging_dir.mkdir(parents=True, exist_ok=True)
                            buf = bytes(lt.write_resume_data_buf(a.params))
                            _atomic_write_bytes(staging_dir / "resume.dat", buf)
                            meta_path = staging_dir / "meta.torrent"
                            if not meta_path.exists() and getattr(a.params, "ti", None) is not None:
                                self.save_torrent_metadata(a.params.ti, meta_path)
                            if waiter:
                                waiter["success"] = True
                        except Exception as exc:
                            logger.warning(f"Failed writing resume.dat for {ih}: {exc}")
                            if waiter:
                                waiter["success"] = False
                                waiter["error"] = str(exc)
                    if waiter:
                        waiter["event"].set()
                elif isinstance(a, lt.save_resume_data_failed_alert):
                    ih = _get_ih_hex(a.handle)
                    waiter = self._resume_waiters.get(ih)
                    if waiter:
                        waiter["success"] = False
                        waiter["error"] = a.message()
                        waiter["event"].set()

    def build_magnet_metadata_params(self, magnet_uri: str) -> lt.add_torrent_params:
        """
        Builds add_torrent_params following qBittorrent's zero-payload magnet metadata pattern:
        - Clears auto_managed, paused, and stop_when_ready so libtorrent enters downloading_metadata.
        - Sets upload_mode + default_dont_download + 0 file_priorities so zero payload bytes are downloaded.
        - Appends public fallback trackers in case embedded magnet trackers are unreachable.
        """
        params = lt.parse_magnet_uri(magnet_uri)
        params.save_path = str(self.metadata_dir)

        params.flags &= ~(
            lt.torrent_flags.auto_managed |
            lt.torrent_flags.paused |
            lt.torrent_flags.stop_when_ready
        )
        params.flags |= (
            lt.torrent_flags.upload_mode |
            lt.torrent_flags.default_dont_download
        )
        params.file_priorities = [0] * 1000

        existing_trackers = list(params.trackers) if hasattr(params, "trackers") else []
        for tr in PUBLIC_FALLBACK_TRACKERS:
            if tr not in existing_trackers:
                existing_trackers.append(tr)
        params.trackers = existing_trackers

        return params

    def fetch_magnet_metadata(self, magnet_uri, timeout_seconds=60, cancel_check=None, status_callback=None):
        """
        Resolves torrent metadata from a Magnet URI with ZERO payload data downloaded.
        Caches resolved metadata to _metadata_cache/<info_hash>.torrent.
        """
        params = self.build_magnet_metadata_params(magnet_uri)
        ih = _get_ih_hex(params) or extract_info_hash(magnet_uri) or ""
        waiter = {"event": threading.Event(), "ti": None}
        if ih:
            with self._pump_lock:
                self._metadata_waiters[ih] = waiter

        handle = self.ses.add_torrent(params)

        try:
            try:
                handle.force_reannounce()
                handle.force_dht_announce()
            except Exception:
                pass

            start_time = time.time()
            last_status_time = 0.0

            while True:
                self.pump_alerts()

                if cancel_check and cancel_check():
                    raise InterruptedError("Magnet metadata lookup cancelled by user.")

                if not handle.is_valid():
                    raise RuntimeError("Torrent handle became invalid while fetching metadata.")

                st = handle.status()
                if st.has_metadata or waiter["event"].is_set():
                    break

                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    raise TimeoutError(f"Timed out fetching magnet metadata after {timeout_seconds}s")

                if status_callback and (time.time() - last_status_time >= 0.5):
                    last_status_time = time.time()
                    try:
                        dht_nodes = self.ses.status().dht_nodes
                    except Exception:
                        dht_nodes = 0
                    status_callback(
                        f"Searching DHT & trackers... "
                        f"(Peers: {st.num_peers}, DHT nodes: {dht_nodes}, {int(elapsed)}s / {int(timeout_seconds)}s)"
                    )

                time.sleep(0.15)

            ti = waiter["ti"] or handle.torrent_file()
            resolved_ti = lt.torrent_info(ti)
            resolved_ih = _get_ih_hex(resolved_ti) or ih
            if resolved_ih:
                self.save_torrent_metadata(
                    resolved_ti,
                    self.metadata_dir / f"{resolved_ih}.torrent",
                    extra_trackers=list(params.trackers) if hasattr(params, "trackers") else None,
                )
            return resolved_ti
        finally:
            if ih:
                with self._pump_lock:
                    self._metadata_waiters.pop(ih, None)
            if handle.is_valid():
                try:
                    self.ses.remove_torrent(handle)
                except Exception:
                    pass

    def load_torrent_file(self, torrent_file_path):
        """Loads torrent_info directly from a local .torrent file."""
        return lt.torrent_info(str(torrent_file_path))

    def merge_trackers(self, task_id, magnet_uri: str) -> int:
        """Merges trackers from a duplicate magnet URI into an active handle."""
        handle = self.active_handles.get(task_id)
        if not handle or not handle.is_valid() or not magnet_uri or not magnet_uri.lower().startswith("magnet:"):
            return 0
        try:
            params = lt.parse_magnet_uri(magnet_uri)
            existing = {tr.get("url") for tr in handle.trackers()} if hasattr(handle, "trackers") else set()
            added = 0
            for tr in getattr(params, "trackers", []):
                if tr and tr not in existing:
                    handle.add_tracker({"url": tr})
                    existing.add(tr)
                    added += 1
            return added
        except Exception:
            return 0

    def add_active_torrent(self, task_id, source, staging_path, file_priorities=None,
                           sequential=False, torrent_path=None, info_hash=None, start_paused=False):
        """
        Adds torrent to active session with staging save_path, or updates/resumes an
        existing valid handle already tracked for task_id.
        Rehydrates cold-restarted handles cleanly from resume.dat + meta.torrent.
        """
        existing_handle = self.active_handles.get(task_id)
        if existing_handle and existing_handle.is_valid():
            if start_paused:
                existing_handle.unset_flags(lt.torrent_flags.auto_managed)
                existing_handle.pause()
            else:
                existing_handle.unset_flags(lt.torrent_flags.paused)
                existing_handle.set_flags(lt.torrent_flags.auto_managed)
                existing_handle.resume()
            if sequential:
                existing_handle.set_flags(lt.torrent_flags.sequential_download)
            else:
                existing_handle.unset_flags(lt.torrent_flags.sequential_download)
            if file_priorities and existing_handle.status().has_metadata:
                existing_handle.prioritize_files(file_priorities)
            return existing_handle

        staging_dir = Path(staging_path)
        staging_dir.mkdir(parents=True, exist_ok=True)
        resume_file = staging_dir / "resume.dat"
        meta_file = staging_dir / "meta.torrent"

        expected_ih = (info_hash or "").lower() or (extract_info_hash(source) if isinstance(source, str) else _get_ih_hex(source))

        # Resolve torrent_info if available from source, meta.torrent, or metadata cache
        ti = None
        magnet_trackers = []
        if isinstance(source, lt.torrent_info):
            ti = source
        elif isinstance(source, str) and source.lower().startswith("magnet:"):
            try:
                mp = lt.parse_magnet_uri(source)
                magnet_trackers = list(mp.trackers) if hasattr(mp, "trackers") else []
            except Exception:
                pass
        elif isinstance(source, str) and os.path.exists(source):
            ti = lt.torrent_info(source)

        if ti is None and torrent_path and os.path.exists(str(torrent_path)):
            try:
                ti = lt.torrent_info(str(torrent_path))
            except Exception:
                ti = None
        if ti is None and meta_file.exists():
            try:
                ti = lt.torrent_info(str(meta_file))
            except Exception:
                ti = None
        if ti is None and expected_ih:
            cached = self.metadata_dir / f"{expected_ih}.torrent"
            if cached.exists():
                try:
                    ti = lt.torrent_info(str(cached))
                except Exception:
                    ti = None

        # Always persist meta.torrent alongside staging folder when ti is available
        if ti is not None and not meta_file.exists():
            self.save_torrent_metadata(ti, meta_file, extra_trackers=magnet_trackers or None)

        params = None
        if resume_file.exists():
            try:
                with open(resume_file, "rb") as f:
                    candidate = lt.read_resume_data(f.read())
                resume_ih = _get_ih_hex(candidate)
                # Guard against contaminated resume.dat belonging to another info_hash
                if expected_ih and resume_ih and resume_ih != expected_ih:
                    logger.warning(f"Task {task_id}: Ignoring mismatched resume.dat ({resume_ih} != {expected_ih})")
                    params = None
                else:
                    params = candidate
            except Exception as exc:
                logger.warning(f"Task {task_id}: Corrupt resume.dat ignored: {exc}")
                params = None

        if params is not None and getattr(params, "ti", None) is None and ti is not None:
            params.ti = ti

        if params is None:
            if ti is not None:
                params = lt.add_torrent_params()
                params.ti = ti
                if magnet_trackers:
                    params.trackers = magnet_trackers
            elif isinstance(source, str) and source.lower().startswith("magnet:"):
                params = lt.parse_magnet_uri(source)
                existing_trackers = list(params.trackers) if hasattr(params, "trackers") else []
                for tr in PUBLIC_FALLBACK_TRACKERS:
                    if tr not in existing_trackers:
                        existing_trackers.append(tr)
                params.trackers = existing_trackers
            else:
                raise ValueError("Invalid torrent source")
        elif isinstance(source, str) and source.lower().startswith("magnet:") and not list(getattr(params, "trackers", [])):
            if magnet_trackers:
                params.trackers = magnet_trackers

        params.save_path = str(staging_dir)
        if start_paused:
            params.flags &= ~lt.torrent_flags.auto_managed
            params.flags |= lt.torrent_flags.paused
        else:
            params.flags &= ~lt.torrent_flags.paused
            params.flags |= lt.torrent_flags.auto_managed

        if sequential:
            params.flags |= lt.torrent_flags.sequential_download
        else:
            params.flags &= ~lt.torrent_flags.sequential_download

        if file_priorities and getattr(params, "ti", None) is not None:
            num_files = params.ti.num_files()
            if len(file_priorities) == num_files:
                params.file_priorities = list(file_priorities)

        handle = self.ses.add_torrent(params)
        ih_hex = _get_ih_hex(handle) or expected_ih
        if ih_hex:
            with self._pump_lock:
                self._handle_staging[ih_hex] = staging_dir

        if file_priorities and handle.status().has_metadata:
            handle.prioritize_files(file_priorities)

        try:
            if getattr(self, "_max_peers_per_torrent", 0) > 0:
                handle.set_max_connections(int(self._max_peers_per_torrent))
        except Exception:
            pass

        self.active_handles[task_id] = handle
        return handle

    def apply_settings(self, config) -> dict:
        """
        Applies BitTorrent network, encryption, and connection limits from Config
        onto the live libtorrent 2.1.1.0 session and active handles.
        """
        port = int(getattr(config, "bt_listen_port", 6881) or 0)
        enable_dht = bool(getattr(config, "bt_enable_dht", True))
        enable_pex_lsd = bool(getattr(config, "bt_enable_pex_lsd", True))
        enable_upnp = bool(getattr(config, "bt_enable_upnp", True))
        enc_mode = str(getattr(config, "bt_encryption_mode", "prefer") or "prefer").lower()
        max_conns = max(10, int(getattr(config, "bt_max_connections", 200) or 200))
        max_peers_per = max(5, int(getattr(config, "bt_max_peers_per_torrent", 60) or 60))

        if enc_mode in ("require", "forced"):
            enc_policy = int(lt.enc_policy.pe_forced)
        elif enc_mode in ("disabled", "off"):
            enc_policy = int(lt.enc_policy.pe_disabled)
        else:
            enc_policy = int(lt.enc_policy.pe_enabled)

        pack = {
            "listen_interfaces": f"0.0.0.0:{port},[::]:{port}",
            "enable_dht": enable_dht,
            "enable_lsd": enable_pex_lsd,
            "enable_upnp": enable_upnp,
            "enable_natpmp": enable_upnp,
            "in_enc_policy": enc_policy,
            "out_enc_policy": enc_policy,
            "allowed_enc_level": int(lt.enc_level.pe_both),
            "connections_limit": max_conns,
        }
        self.ses.apply_settings(pack)
        self._max_peers_per_torrent = max_peers_per

        for handle in list(self.active_handles.values()):
            try:
                if handle and handle.is_valid():
                    handle.set_max_connections(max_peers_per)
            except Exception:
                pass
        return pack

    def save_resume_data(self, task_id, staging_path, timeout_seconds=2.5, flush_cache=False):
        handle = self.active_handles.get(task_id)
        if not handle or not handle.is_valid():
            return False

        staging_dir = Path(staging_path)
        ih = _get_ih_hex(handle)
        if not ih:
            return False

        waiter = {
            "event": threading.Event(),
            "success": False,
            "error": None,
            "staging_path": staging_dir,
        }
        with self._pump_lock:
            self._handle_staging[ih] = staging_dir
            self._resume_waiters[ih] = waiter

        try:
            resume_exists = (staging_dir / "resume.dat").exists()
            flags = lt.save_resume_flags_t.save_info_dict
            if flush_cache or not resume_exists:
                flags |= lt.save_resume_flags_t.flush_disk_cache
            else:
                flags |= lt.save_resume_flags_t.only_if_modified

            handle.save_resume_data(flags)
            deadline = time.time() + timeout_seconds
            while time.time() < deadline:
                self.pump_alerts()
                if waiter["event"].is_set():
                    return bool(waiter["success"])
                time.sleep(0.05)
        except Exception as exc:
            logger.warning(f"save_resume_data error for {task_id}: {exc}")
        finally:
            with self._pump_lock:
                self._resume_waiters.pop(ih, None)
        return False

    def pause_torrent(self, task_id, staging_path=None):
        handle = self.active_handles.get(task_id)
        if handle and handle.is_valid():
            handle.unset_flags(lt.torrent_flags.auto_managed)
            handle.pause()
            target_staging = staging_path
            if target_staging is None:
                ih = _get_ih_hex(handle)
                target_staging = self._handle_staging.get(ih)
            if target_staging:
                self.save_resume_data(task_id, target_staging, flush_cache=True)

    def resume_torrent(self, task_id):
        handle = self.active_handles.get(task_id)
        if handle and handle.is_valid():
            handle.unset_flags(lt.torrent_flags.paused)
            handle.set_flags(lt.torrent_flags.auto_managed)
            handle.resume()

    def remove_torrent(self, task_id, delete_files=False):
        handle = self.active_handles.get(task_id)
        if handle and handle.is_valid():
            ih = _get_ih_hex(handle)
            if ih:
                with self._pump_lock:
                    self._handle_staging.pop(ih, None)
            if delete_files:
                self.ses.remove_torrent(handle, lt.session.delete_files)
            else:
                self.ses.remove_torrent(handle)
        if task_id in self.active_handles:
            del self.active_handles[task_id]

    def set_speed_limit(self, download_kbs: int = 0, upload_kbs: int = 0):
        """Applies global download/upload rate limits to libtorrent session (0 = unlimited)."""
        try:
            settings = self.ses.get_settings()
            settings['download_rate_limit'] = download_kbs * 1024 if download_kbs > 0 else 0
            settings['upload_rate_limit'] = upload_kbs * 1024 if upload_kbs > 0 else 0
            self.ses.apply_settings(settings)
        except Exception:
            pass

    def flush_all_sessions(self, timeout: float = 5.0):
        """
        Synchronously pauses every active torrent handle, triggers save_resume_data
        with flush_disk_cache | save_info_dict, and pumps alerts until every handle
        confirms persistence or the deadline expires.
        """
        pending_waiters = {}
        flags = lt.save_resume_flags_t.flush_disk_cache | lt.save_resume_flags_t.save_info_dict

        with self._pump_lock:
            for tid, handle in list(self.active_handles.items()):
                if not handle or not handle.is_valid():
                    continue
                ih = _get_ih_hex(handle)
                staging_path = self._handle_staging.get(ih)
                if not staging_path:
                    try:
                        sp = handle.status().save_path
                        if sp:
                            staging_path = Path(sp)
                    except Exception:
                        pass
                if not ih or not staging_path:
                    continue
                try:
                    handle.unset_flags(lt.torrent_flags.auto_managed)
                    handle.pause()
                    waiter = {
                        "event": threading.Event(),
                        "success": False,
                        "error": None,
                        "staging_path": Path(staging_path),
                    }
                    self._resume_waiters[ih] = waiter
                    pending_waiters[ih] = waiter
                    handle.save_resume_data(flags)
                except Exception as exc:
                    logger.warning(f"flush_all_sessions trigger failed for {tid}: {exc}")

        if not pending_waiters:
            return

        deadline = time.time() + max(0.5, timeout)
        while time.time() < deadline:
            self.pump_alerts()
            if all(w["event"].is_set() for w in pending_waiters.values()):
                break
            time.sleep(0.05)

        with self._pump_lock:
            for ih in pending_waiters:
                self._resume_waiters.pop(ih, None)
