"""
OmniFetch BitTorrent Worker (PySide6 QThread)
Manages libtorrent active torrent execution, progress polling, auto-stop seeding,
and triggers CyberShield Stage 3 per-file inspection upon completion.
"""

import os
import time
import shutil
from pathlib import Path
from PySide6.QtCore import QThread, Signal
import libtorrent as lt

from .session import TorrentSessionManager, _get_ih_hex
from ...core.security_gate import SecurityGate

SCAN_EXTENSIONS = {
    '.exe', '.dll', '.msi', '.bat', '.cmd', '.scr',
    '.pif', '.vbs', '.hta', '.ps1', '.zip', '.rar', '.7z',
    '.ini', '.cfg', '.nfo'
}

class TorrentDownloadWorker(QThread):
    progress_signal = Signal(dict)
    status_signal = Signal(str, str)
    finished_signal = Signal(str, dict)
    error_signal = Signal(str, str)

    def __init__(self, task_id, db, staging_manager, security_gate: SecurityGate,
                 source, file_priorities=None, sequential=False, stop_ratio=None,
                 torrent_path=None, info_hash=None, session_mgr=None):
        super().__init__()
        self.task_id = task_id
        self.db = db
        self.staging_manager = staging_manager
        self.security_gate = security_gate
        self.source = source
        self.file_priorities = file_priorities
        self.sequential = sequential
        self.stop_ratio = 0.0 if stop_ratio is None else float(stop_ratio)
        self.torrent_path = torrent_path
        self.info_hash = info_hash
        self.is_running = True
        self._metadata_name_updated = False
        self.session_mgr = session_mgr or TorrentSessionManager.get_instance(staging_manager.base_staging_dir)

    def stop(self):
        self.is_running = False

    def pause(self):
        self.is_running = False
        staging_dir = self.staging_manager.allocate_task_staging(self.task_id)
        self.session_mgr.pause_torrent(self.task_id, str(staging_dir))

    def run(self):
        task = self.db.get_task(self.task_id)
        if not task:
            self.error_signal.emit(self.task_id, f"Task {self.task_id} not found")
            return

        staging_dir = self.staging_manager.allocate_task_staging(self.task_id)
        prev_downloaded = task.get("downloaded_bytes", 0) or 0
        prev_total = task.get("total_bytes", 0) or 0

        try:
            # Cold-restart recovery for interrupted Stage 3 STAGED/SCANNING tasks
            if task.get("status") in ("STAGED", "SCANNING"):
                self.status_signal.emit(self.task_id, "SCANNING")
                self.db.update_task_status(self.task_id, "SCANNING")
                gate_results = self._process_stage3_torrent(staging_dir, task["destination"])
                self.session_mgr.remove_torrent(self.task_id, delete_files=False)
                self.status_signal.emit(self.task_id, "COMPLETED")
                self.finished_signal.emit(self.task_id, gate_results)
                return

            handle = self.session_mgr.add_active_torrent(
                task_id=self.task_id,
                source=self.source,
                staging_path=str(staging_dir),
                file_priorities=self.file_priorities,
                sequential=self.sequential,
                torrent_path=self.torrent_path or task.get("torrent_path"),
                info_hash=self.info_hash or task.get("info_hash"),
                start_paused=False,
            )

            self.db.update_task_resumable(self.task_id, 1)
            self.status_signal.emit(self.task_id, "DOWNLOADING")
            self.db.update_task_status(self.task_id, "DOWNLOADING")
            last_resume_save = time.time()

            while self.is_running:
                time.sleep(0.5)
                self.session_mgr.pump_alerts()
                if not handle.is_valid():
                    break

                s = handle.status()

                # If metadata just resolved, save meta.torrent + filename + info_hash in SQLite
                if s.has_metadata:
                    if not self._metadata_name_updated:
                        try:
                            ti = handle.torrent_file()
                            real_name = ti.name() if ti else s.name
                            ih_hex = _get_ih_hex(ti) or _get_ih_hex(handle)
                            meta_path = staging_dir / "meta.torrent"
                            if ti and not meta_path.exists():
                                self.session_mgr.save_torrent_metadata(ti, meta_path)
                            updates = {"resumable": 1}
                            if ih_hex:
                                updates["info_hash"] = ih_hex
                            if meta_path.exists():
                                updates["torrent_path"] = str(meta_path)
                            if real_name:
                                task_row = self.db.get_task(self.task_id)
                                if task_row and task_row.get("filename") in ("Magnet Download", "torrent_download", "", None):
                                    updates["filename"] = real_name
                            self.db.update_task_fields(self.task_id, **updates)
                            self._metadata_name_updated = True
                        except Exception:
                            pass

                    if self.file_priorities:
                        handle.prioritize_files(self.file_priorities)
                        self.db.update_task_fields(self.task_id, file_priorities=self.file_priorities)
                        self.file_priorities = None

                # Do not clobber existing progress while libtorrent is still checking files/resume
                is_checking = s.state in (
                    lt.torrent_status.checking_files,
                    lt.torrent_status.checking_resume_data,
                    lt.torrent_status.downloading_metadata,
                )
                downloaded = s.total_done
                total = s.total_wanted if s.total_wanted > 0 else s.total

                if is_checking and downloaded == 0 and prev_downloaded > 0:
                    downloaded = prev_downloaded
                    if total <= 0 and prev_total > 0:
                        total = prev_total
                elif downloaded > 0:
                    prev_downloaded = downloaded

                speed = s.download_rate
                eta = int((total - downloaded) / speed) if speed > 0 and total > downloaded else 0

                self.db.update_task_progress(
                    task_id=self.task_id,
                    downloaded_bytes=downloaded,
                    total_bytes=total,
                    speed_bps=speed,
                    eta_seconds=eta
                )

                self.progress_signal.emit({
                    "task_id": self.task_id,
                    "downloaded": downloaded,
                    "total": total,
                    "speed": speed,
                    "eta": eta,
                    "seeds": s.num_seeds,
                    "peers": s.num_peers,
                    "ratio": (s.all_time_upload / max(1, s.all_time_download))
                })

                # Periodic checkpoint every 15s for crash resilience
                if time.time() - last_resume_save >= 15.0:
                    self.session_mgr.save_resume_data(self.task_id, str(staging_dir), timeout_seconds=0.8)
                    last_resume_save = time.time()

                # Check if download is complete (is_seeding or 100% of wanted pieces done; ignore metadata/checking)
                if s.has_metadata and not is_checking and (s.is_seeding or (total > 0 and downloaded >= total)):
                    ratio = s.all_time_upload / max(1, s.all_time_download)
                    if self.stop_ratio >= 0.0 and (self.stop_ratio == 0.0 or ratio >= self.stop_ratio):
                        handle.unset_flags(lt.torrent_flags.auto_managed)
                        handle.pause()
                        break

            if not self.is_running:
                self.session_mgr.pause_torrent(self.task_id, str(staging_dir))
                self.db.update_task_status(self.task_id, "PAUSED")
                self.status_signal.emit(self.task_id, "PAUSED")
                return

            # Save final resume data upon completion
            self.session_mgr.save_resume_data(self.task_id, str(staging_dir), flush_cache=True)

            # Stage 3 Security Gate Inspection across all staged files
            self.status_signal.emit(self.task_id, "SCANNING")
            self.db.update_task_status(self.task_id, "SCANNING")

            final_dest = task["destination"]
            gate_results = self._process_stage3_torrent(staging_dir, final_dest)

            # Cleanup staging folder if empty
            try:
                if staging_dir.exists() and not any(staging_dir.iterdir()):
                    staging_dir.rmdir()
            except Exception:
                pass

            self.session_mgr.remove_torrent(self.task_id, delete_files=False)
            self.status_signal.emit(self.task_id, "COMPLETED")
            self.finished_signal.emit(self.task_id, gate_results)

        except Exception as e:
            self.error_signal.emit(self.task_id, str(e))
            self.status_signal.emit(self.task_id, "FAILED")
            self.db.update_task_status(self.task_id, "FAILED", error_message=str(e))

    def _process_stage3_torrent(self, staging_dir: Path, destination_dir: str):
        """
        Scans all downloaded files in staging:
        - Quarantines CRITICAL files into CyberShield's vault.
        - Fails-closed on SCAN_ERROR (holds unverified files in .staging).
        - Moves LOW (game cracks) and CLEAN files to final destination, preserving subfolders.
        """
        dest_root = Path(destination_dir)
        dest_root.mkdir(parents=True, exist_ok=True)

        scanned_files = []
        critical_count = 0
        warning_count = 0
        clean_count = 0
        scan_errors = []

        # Walk all files inside staging directory
        for root, dirs, files in os.walk(str(staging_dir)):
            for f in files:
                if f in ("resume.dat", "meta.torrent") or ".tmp." in f:
                    continue  # Ignore internal libtorrent metadata/resume files

                full_path = Path(root) / f
                rel_path = full_path.relative_to(staging_dir)
                dest_file_path = dest_root / rel_path
                dest_file_path.parent.mkdir(parents=True, exist_ok=True)

                ext = full_path.suffix.lower()
                is_known_config = full_path.name.lower() in ("steam_emu.ini", "codex.ini", "flt.ini", "rune.ini", "rld.ini")
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
                        continue  # Do not copy to destination

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
                        continue  # Fail closed: hold unverified file in staging
                else:
                    clean_count += 1
                    scanned_files.append({"file": str(rel_path), "verdict": "CLEAN"})

                # Move clean/warning file into destination folder
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

        # Update overall security status in SQLite
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
