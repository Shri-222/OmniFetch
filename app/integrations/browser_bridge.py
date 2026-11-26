"""
OmniFetch Brave Browser Handoff Bridge
Lightweight 127.0.0.1 HTTP service providing authenticated download handoff:
- GET /api/ping: Heartbeat check for extension.
- POST /api/handoff: Secure link submission with Cookie, Referer, and User-Agent forwarding.
Protected with persisted X-OmniFetch-Token header.
"""

import json
import time
import asyncio
import threading
from aiohttp import web
from PySide6.QtCore import QObject, Signal, Qt

from ..core.config import Config
from ..core.engine_manager import EngineManager
from ..core.logger import get_logger
from ..engines.mega.resolver import MegaUrlResolver

logger = get_logger("browser_bridge")

class BrowserHandoffBridge(QObject):
    start_task_requested = Signal(str)           # task_id, queued to Qt GUI thread
    download_received = Signal(str, str)         # url, task_id
    magnet_handoff_requested = Signal(str, str)  # magnet_url, filename
    refresh_link_received = Signal(str, str, dict)  # task_id, new_url, headers
    pairing_completed = Signal()

    def __init__(self, config: Config, engine_manager: EngineManager, parent=None):
        super().__init__(parent)
        self.config = config
        self.engine_manager = engine_manager
        self.port = self.config.brave_handoff_port
        self.token = self.config.brave_handoff_token
        self._runner = None
        self._loop = None
        self._thread = None
        self._is_running = False
        self.magnet_inspector_enabled = False
        self.pending_refresh_task_id = None
        self._pairing_expires_at = 0.0
        self._pairing_lock = threading.Lock()

        # Connect task start signal safely across threads to GUI thread
        self.start_task_requested.connect(self.engine_manager.start_download, Qt.QueuedConnection)

    def open_pairing_window(self, duration_seconds: int = 60) -> float:
        with self._pairing_lock:
            self._pairing_expires_at = time.time() + max(1, int(duration_seconds))
            return self._pairing_expires_at

    def close_pairing_window(self):
        with self._pairing_lock:
            self._pairing_expires_at = 0.0

    def is_pairing_open(self) -> bool:
        with self._pairing_lock:
            return time.time() < self._pairing_expires_at

    def _cors_headers(self) -> dict:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-OmniFetch-Token"
        }

    async def _handle_options(self, request):
        return web.Response(headers=self._cors_headers())

    async def _handle_ping(self, request):
        # Authenticate via secret X-OmniFetch-Token header or query param
        auth_header = request.headers.get("X-OmniFetch-Token") or request.query.get("token")
        if not auth_header or auth_header != self.config.brave_handoff_token:
            return web.json_response(
                {"error": "Unauthorized: Invalid or missing X-OmniFetch-Token"},
                status=401,
                headers=self._cors_headers()
            )
        data = {
            "status": "ok",
            "app": "OmniFetch",
            "version": "1.0.0",
            "port": self.port,
            "pending_refresh_task_id": self.pending_refresh_task_id,
        }
        return web.json_response(data, headers=self._cors_headers())

    async def _apply_refresh_link(self, target_task_id: str, url: str, body: dict):
        cookies = body.get("cookies")
        referer = body.get("referer")
        user_agent = body.get("userAgent")
        custom_headers = {}
        if cookies:
            custom_headers["Cookie"] = cookies
        if referer:
            custom_headers["Referer"] = referer
        if user_agent:
            custom_headers["User-Agent"] = user_agent

        res = self.engine_manager.refresh_download_address(target_task_id, url, custom_headers=custom_headers)
        if not res.get("success"):
            return web.json_response(
                {"status": "error", "success": False, "error": res.get("reason", "Incompatible refresh URL"), "task_id": target_task_id},
                status=409,
                headers=self._cors_headers()
            )
        if self.pending_refresh_task_id == target_task_id:
            self.pending_refresh_task_id = None
        self.refresh_link_received.emit(target_task_id, url, custom_headers)
        self.start_task_requested.emit(target_task_id)
        return web.json_response(
            {"status": "ok", "success": True, "refreshed_task_id": target_task_id, "task_id": target_task_id, "url": url},
            headers=self._cors_headers()
        )

    async def _handle_refresh_link(self, request):
        auth_header = request.headers.get("X-OmniFetch-Token") or request.query.get("token")
        if not auth_header or auth_header != self.config.brave_handoff_token:
            return web.json_response(
                {"error": "Unauthorized: Invalid or missing X-OmniFetch-Token"},
                status=401,
                headers=self._cors_headers()
            )
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400, headers=self._cors_headers())

        url = (body.get("url") or "").strip()
        target_task_id = request.query.get("task_id") or body.get("task_id") or body.get("replace_task_id") or self.pending_refresh_task_id
        if not url or not target_task_id:
            return web.json_response({"error": "Missing url or task_id"}, status=400, headers=self._cors_headers())
        return await self._apply_refresh_link(str(target_task_id), url, body)

    async def _handle_handoff(self, request):
        # Authenticate via secret X-OmniFetch-Token header
        auth_header = request.headers.get("X-OmniFetch-Token") or request.query.get("token")
        if not auth_header or auth_header != self.config.brave_handoff_token:
            return web.json_response(
                {"error": "Unauthorized: Invalid or missing X-OmniFetch-Token"},
                status=401,
                headers=self._cors_headers()
            )

        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": "Invalid JSON body"},
                status=400,
                headers=self._cors_headers()
            )

        url = body.get("url", "").strip()
        if not url:
            return web.json_response(
                {"error": "Missing URL"},
                status=400,
                headers=self._cors_headers()
            )

        if url.startswith("blob:") or url.startswith("data:"):
            logger.warning(f"Rejected unsupported browser memory URL: {url[:30]}...")
            return web.json_response(
                {"error": "blob: and data: URLs are internal browser memory objects and cannot be downloaded externally."},
                status=400,
                headers=self._cors_headers()
            )

        replace_task_id = request.query.get("replace_task_id") or body.get("replace_task_id")
        if replace_task_id:
            return await self._apply_refresh_link(str(replace_task_id), url, body)

        filename = body.get("filename")
        cookies = body.get("cookies")
        referer = body.get("referer")
        user_agent = body.get("userAgent")

        # Build custom forwarding headers
        custom_headers = {}
        if cookies:
            custom_headers["Cookie"] = cookies
        if referer:
            custom_headers["Referer"] = referer
        if user_agent:
            custom_headers["User-Agent"] = user_agent

        task_id = None
        if url.startswith("magnet:"):
            if self.magnet_inspector_enabled:
                logger.info(f"Magnet handoff routed to Stage 1 Torrent Inspector: {url[:60]}")
                self.magnet_handoff_requested.emit(url, filename or "Magnet Download")
                return web.json_response(
                    {
                        "status": "ok",
                        "success": True,
                        "mode": "magnet_inspection",
                        "task_id": None,
                        "url": url,
                        "filename": filename,
                    },
                    headers=self._cors_headers()
                )
            task_id = self.engine_manager.add_download(url=url, filename=filename or "Magnet Download", engine_type="TORRENT")
            self.start_task_requested.emit(task_id)
        elif MegaUrlResolver.is_mega_url(url):
            task_id = self.engine_manager.add_mega_download(url=url, filename=filename)
            self.start_task_requested.emit(task_id)
        else:
            task_id = self.engine_manager.add_download(
                url=url,
                filename=filename,
                custom_headers=custom_headers
            )
            self.start_task_requested.emit(task_id)

        logger.info(f"Handoff received: {url} -> Task #{task_id} (queued to GUI thread)")
        self.download_received.emit(url, task_id or "")

        return web.json_response(
            {
                "status": "ok",
                "success": True,
                "task_id": task_id,
                "url": url,
                "filename": filename
            },
            headers=self._cors_headers()
        )

    async def _handle_pair(self, request):
        # Strictly restrict pairing to local loopback + chrome-extension:// origin + open single-use window
        remote = (request.remote or "").strip()
        if remote not in ("127.0.0.1", "::1", ""):
            return web.json_response(
                {"error": "Forbidden: Pairing is strictly restricted to 127.0.0.1."},
                status=403,
                headers=self._cors_headers(),
            )
        origin = (request.headers.get("Origin") or "").strip()
        if not origin.lower().startswith("chrome-extension://"):
            return web.json_response(
                {"error": "Forbidden: Pairing is strictly restricted to chrome-extension:// origins."},
                status=403,
                headers=self._cors_headers(),
            )

        with self._pairing_lock:
            if time.time() >= self._pairing_expires_at:
                self._pairing_expires_at = 0.0
                return web.json_response(
                    {"error": "Pairing window is closed. Click 'Pair Brave Extension (60s)' in OmniFetch Settings."},
                    status=403,
                    headers=self._cors_headers(),
                )
            # Single-use consumption: close window immediately
            self._pairing_expires_at = 0.0

        self.pairing_completed.emit()
        return web.json_response(
            {
                "status": "ok",
                "success": True,
                "token": self.config.brave_handoff_token,
                "port": self.port,
            },
            headers=self._cors_headers(),
        )

    def start(self) -> bool:
        if self._is_running:
            return True

        ready = threading.Event()

        def run_server():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            app = web.Application()
            app.router.add_options("/api/ping", self._handle_options)
            app.router.add_get("/api/ping", self._handle_ping)
            app.router.add_options("/api/handoff", self._handle_options)
            app.router.add_post("/api/handoff", self._handle_handoff)
            app.router.add_options("/api/refresh-link", self._handle_options)
            app.router.add_post("/api/refresh-link", self._handle_refresh_link)
            app.router.add_options("/api/pair", self._handle_options)
            app.router.add_post("/api/pair", self._handle_pair)

            self._runner = web.AppRunner(app)
            self._loop.run_until_complete(self._runner.setup())
            site = web.TCPSite(self._runner, "127.0.0.1", self.port)
            self._loop.run_until_complete(site.start())
            self._is_running = True
            ready.set()
            try:
                self._loop.run_forever()
            finally:
                try:
                    if self._runner:
                        self._loop.run_until_complete(self._runner.cleanup())
                except Exception:
                    pass
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.close()

        self._thread = threading.Thread(target=run_server, daemon=True)
        self._thread.start()
        ready.wait(timeout=3.0)
        return True

    def stop(self):
        if self._is_running and self._loop and not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._is_running = False
