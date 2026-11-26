"""
OmniFetch Optional FFmpeg HLS (.m3u8) Stream Remuxer
Detects system ffmpeg via PATH (zero bundled unsigned binaries), forwards browser
headers (User-Agent, Referer, Cookie), remuxes .m3u8 streams into playable .mp4
inside .staging/<task_id>/, and routes final output through CyberShield Stage 3.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from PySide6.QtCore import QThread, Signal


def find_ffmpeg() -> str | None:
    """Finds system ffmpeg executable on PATH without bundling binaries."""
    return shutil.which("ffmpeg")


def is_hls_url(url: str | None) -> bool:
    """Returns True if URL points to an HLS .m3u8 playlist."""
    if not url or not isinstance(url, str):
        return False
    low = url.strip().lower()
    if not low.startswith(("http://", "https://")):
        return False
    try:
        path = urlparse(low).path
        return path.endswith(".m3u8") or ".m3u8" in path
    except Exception:
        return ".m3u8" in low


def build_ffmpeg_hls_command(
    ffmpeg_exe: str,
    url: str,
    output_mp4: str,
    custom_headers: dict | None = None,
) -> list[str]:
    """
    Constructs clean FFmpeg HLS -> MP4 remux CLI command preserving forwarded
    HTTP headers (User-Agent, Referer, Cookie).
    """
    cmd = [ffmpeg_exe, "-y", "-hide_banner", "-loglevel", "warning", "-progress", "pipe:1", "-nostats"]
    if custom_headers and isinstance(custom_headers, dict):
        ua = custom_headers.get("User-Agent") or custom_headers.get("user-agent")
        if ua:
            cmd.extend(["-user_agent", str(ua)])
        hdr_lines = []
        for k, v in custom_headers.items():
            if not v or str(k).lower() == "user-agent":
                continue
            hdr_lines.append(f"{k}: {v}")
        if hdr_lines:
            cmd.extend(["-headers", "\r\n".join(hdr_lines) + "\r\n"])
    cmd.extend([
        "-i", url,
        "-c", "copy",
        "-bsf:a", "aac_adtstoasc",
        "-movflags", "+faststart",
        str(output_mp4),
    ])
    return cmd


class HlsRemuxWorker(QThread):
    progress_signal = Signal(dict)
    status_signal = Signal(str, str)
    finished_signal = Signal(str, dict)
    error_signal = Signal(str, str)

    def __init__(self, task_id: str, db, staging_manager, security_gate=None):
        super().__init__()
        self.task_id = task_id
        self.db = db
        self.staging_manager = staging_manager
        self.security_gate = security_gate
        self._cancelled = False
        self._proc = None

    def pause(self):
        self._cancelled = True
        self._terminate_proc()

    def stop(self):
        self._cancelled = True
        self._terminate_proc()

    def cancel(self):
        self._cancelled = True
        self._terminate_proc()

    def _terminate_proc(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self):
        task = self.db.get_task(self.task_id)
        if not task:
            self.error_signal.emit(self.task_id, f"Task {self.task_id} not found")
            return

        ffmpeg_exe = find_ffmpeg()
        if not ffmpeg_exe:
            msg = (
                "FFmpeg not found on system PATH. Install FFmpeg to remux .m3u8 streams into MP4, "
                "or select a direct MP4 stream in Brave."
            )
            self.db.update_task_status(self.task_id, "FAILED", error_message=msg)
            self.status_signal.emit(self.task_id, "FAILED")
            self.error_signal.emit(self.task_id, msg)
            return

        custom_headers = {}
        raw_hdrs = task.get("custom_headers")
        if raw_hdrs:
            try:
                parsed = json.loads(raw_hdrs) if isinstance(raw_hdrs, str) else raw_hdrs
                if isinstance(parsed, dict):
                    custom_headers = parsed
            except Exception:
                pass

        raw_name = task.get("filename") or "stream.mp4"
        stem = Path(raw_name).stem or "stream"
        mp4_name = f"{stem}.mp4" if not raw_name.lower().endswith(".mp4") else raw_name
        self.db.update_task_filename(self.task_id, mp4_name)
        self.db.update_task_resumable(self.task_id, 0)

        staged_file = self.staging_manager.get_staged_file_path(self.task_id, mp4_name)
        cmd = build_ffmpeg_hls_command(ffmpeg_exe, task["url"], str(staged_file), custom_headers=custom_headers)

        self.db.update_task_status(self.task_id, "DOWNLOADING")
        self.status_signal.emit(self.task_id, "DOWNLOADING")

        t_start = time.time()
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            total_bytes_written = 0
            if self._proc.stdout:
                for line in self._proc.stdout:
                    if self._cancelled:
                        self._terminate_proc()
                        break
                    line = line.strip()
                    if line.startswith("total_size="):
                        val = line.split("=", 1)[1].strip()
                        if val.isdigit():
                            total_bytes_written = int(val)
                            dt = max(0.1, time.time() - t_start)
                            speed = total_bytes_written / dt
                            self.db.update_task_progress(
                                self.task_id,
                                total_bytes_written,
                                total_bytes=total_bytes_written,
                                speed_bps=speed,
                                eta_seconds=0,
                            )
                            self.progress_signal.emit({
                                "task_id": self.task_id,
                                "downloaded": total_bytes_written,
                                "total": total_bytes_written,
                                "speed": speed,
                                "eta": 0,
                            })

            rc = self._proc.wait()
            if self._cancelled:
                self.db.update_task_status(self.task_id, "PAUSED")
                self.status_signal.emit(self.task_id, "PAUSED")
                return

            if rc != 0 or not staged_file.exists():
                stderr_txt = self._proc.stderr.read().strip() if self._proc.stderr else ""
                raise RuntimeError(f"FFmpeg HLS remux failed (code {rc}): {stderr_txt[:240]}")

            final_size = staged_file.stat().st_size
            self.db.update_task_progress(self.task_id, final_size, total_bytes=final_size, speed_bps=0.0, eta_seconds=0)

            if self.security_gate:
                self.db.update_task_status(self.task_id, "SCANNING")
                self.status_signal.emit(self.task_id, "SCANNING")
                gate_res = self.security_gate.evaluate_post_download(
                    task_id=self.task_id,
                    staged_file_path=str(staged_file),
                    destination_dir=task["destination"],
                )
                if gate_res.get("action") == "QUARANTINED":
                    self.status_signal.emit(self.task_id, "QUARANTINED")
                    self.finished_signal.emit(self.task_id, gate_res)
                elif gate_res.get("action") == "SCAN_ERROR":
                    self.status_signal.emit(self.task_id, "FAILED")
                    self.error_signal.emit(self.task_id, gate_res.get("error", "Security scan failed"))
                else:
                    self.status_signal.emit(self.task_id, "COMPLETED")
                    self.finished_signal.emit(self.task_id, gate_res)
            else:
                final_path = self.staging_manager.move_to_destination(str(staged_file), task["destination"])
                self.db.update_task_status(self.task_id, "COMPLETED")
                self.status_signal.emit(self.task_id, "COMPLETED")
                self.finished_signal.emit(
                    self.task_id,
                    {"status": "COMPLETED", "action": "MOVED_CLEAN", "final_path": final_path, "filename": mp4_name},
                )
        except Exception as exc:
            self.db.update_task_status(self.task_id, "FAILED", error_message=str(exc))
            self.status_signal.emit(self.task_id, "FAILED")
            self.error_signal.emit(self.task_id, str(exc))
