"""
OmniFetch HTTP Download Worker (Qt QThread)
Executes async multi-segment downloads on a dedicated background thread,
emitting PySide6 signals to keep the UI smooth and responsive.
"""

import asyncio
import threading
from PySide6.QtCore import QThread, Signal
from .downloader import HttpDownloader
from ...core.logger import get_logger

logger = get_logger("http_worker")

class HttpDownloadWorker(QThread):
    progress_signal = Signal(dict)          # {task_id, downloaded, total, speed, eta}
    status_signal = Signal(str, str)        # task_id, status
    finished_signal = Signal(str, dict)     # task_id, result_dict
    error_signal = Signal(str, str)         # task_id, error_message

    def __init__(self, task_id, downloader: HttpDownloader):
        super().__init__()
        self.task_id = task_id
        self.downloader = downloader
        self.cancel_token = {"is_cancelled": False}
        self.loop = None

    def cancel(self):
        self.cancel_token["is_cancelled"] = True

    def pause(self):
        self.cancel_token["is_cancelled"] = True

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        def on_progress(p):
            self.progress_signal.emit(p)

        try:
            self.status_signal.emit(self.task_id, "DOWNLOADING")
            result = self.loop.run_until_complete(
                self.downloader.download_task(
                    task_id=self.task_id,
                    progress_callback=on_progress,
                    cancel_token=self.cancel_token
                )
            )

            if self.cancel_token["is_cancelled"]:
                self.status_signal.emit(self.task_id, "PAUSED")
            elif result.get("status") == "LINK EXPIRED":
                self.status_signal.emit(self.task_id, "LINK EXPIRED")
                self.finished_signal.emit(self.task_id, result)
            elif result.get("action") == "QUARANTINED":
                self.status_signal.emit(self.task_id, "QUARANTINED")
                self.finished_signal.emit(self.task_id, result)
            elif result.get("action") == "SCAN_ERROR":
                self.status_signal.emit(self.task_id, "FAILED")
                self.error_signal.emit(self.task_id, result.get("error", "Security scan failed"))
            elif result.get("status") == "COMPLETED" or result.get("action") in ("MOVED_CLEAN", "MOVED_WARNING"):
                self.status_signal.emit(self.task_id, "COMPLETED")
                self.finished_signal.emit(self.task_id, result)
            else:
                self.finished_signal.emit(self.task_id, result)

        except Exception as e:
            logger.error(f"HttpDownloadWorker for task {self.task_id} failed: {e}", exc_info=True)
            self.error_signal.emit(self.task_id, str(e))
            self.status_signal.emit(self.task_id, "FAILED")
        finally:
            self.loop.close()
