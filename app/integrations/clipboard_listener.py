"""
OmniFetch Smart Batch Clipboard Link Grabber
Monitors the Windows clipboard via PySide6 QClipboard signals (0% polling waste).
Detects single or multi-line batch links:
- BitTorrent Magnets (magnet:?xt=urn:btih:...) & .torrent URLs
- MEGA.nz modern & legacy file and folder URLs
- Direct HTTP/HTTPS downloadable files (.zip, .rar, .7z, .iso, .exe, .msi, .mkv, .mp4, .mp3, .pdf, etc.)
Deduplicates consecutive identical clipboard inputs to prevent popup spam.
"""

import re
import os
from urllib.parse import urlparse, unquote
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from ..engines.mega.resolver import MegaUrlResolver

DOWNLOAD_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.iso', '.img', '.dmg', '.vmdk',
    '.exe', '.msi', '.bat', '.cmd',
    '.mkv', '.mp4', '.avi', '.mov', '.wmv', '.webm',
    '.mp3', '.flac', '.wav', '.aac', '.ogg',
    '.pdf', '.epub', '.mobi', '.doc', '.docx', '.xls', '.xlsx'
}

class ClipboardLinkParser:
    @staticmethod
    def extract_links(text: str) -> list[dict]:
        """
        Parses single or multi-line text and extracts downloadable links:
        magnets, MEGA links, torrent files, and direct downloads.
        Deduplicates within the batch.
        """
        if not text or not isinstance(text, str):
            return []

        # Find raw candidate tokens (space, newline, or tab separated)
        candidates = re.findall(r'(?:magnet:\?xt=urn:btih:[^\s\'"]+|https?://[^\s\'"]+)', text, re.IGNORECASE)
        if not candidates:
            return []

        seen_urls = set()
        results = []

        for url in candidates:
            clean_url = url.strip().strip("'\"<>")
            if clean_url in seen_urls:
                continue

            # 1. BitTorrent Magnet
            if clean_url.lower().startswith("magnet:?"):
                seen_urls.add(clean_url)
                name = "Magnet Download"
                dn_match = re.search(r'[?&]dn=([^&]+)', clean_url)
                if dn_match:
                    name = unquote(dn_match.group(1).replace("+", " "))
                results.append({
                    "url": clean_url,
                    "engine_type": "TORRENT",
                    "filename": name,
                    "source": "MAGNET"
                })
                continue

            # 2. MEGA.nz URL
            if MegaUrlResolver.is_mega_url(clean_url):
                seen_urls.add(clean_url)
                parsed_mega = MegaUrlResolver.parse_url(clean_url)
                m_type = parsed_mega.get("type", "file").upper()
                name = f"MEGA_{m_type}_{parsed_mega.get('id', 'item')}"
                results.append({
                    "url": clean_url,
                    "engine_type": "MEGA",
                    "filename": name,
                    "source": "MEGA"
                })
                continue

            # 3. Direct .torrent URL
            parsed_url = urlparse(clean_url)
            path = unquote(parsed_url.path)
            ext = os.path.splitext(path)[1].lower()

            if ext == ".torrent":
                seen_urls.add(clean_url)
                filename = os.path.basename(path) or "download.torrent"
                results.append({
                    "url": clean_url,
                    "engine_type": "TORRENT",
                    "filename": filename,
                    "source": "TORRENT_FILE"
                })
                continue

            # 4. Direct downloadable file URL
            if ext in DOWNLOAD_EXTENSIONS or any(clean_url.lower().endswith(e) for e in DOWNLOAD_EXTENSIONS):
                seen_urls.add(clean_url)
                filename = os.path.basename(path) or "download.bin"
                results.append({
                    "url": clean_url,
                    "engine_type": "HTTP",
                    "filename": filename,
                    "source": "DIRECT_URL"
                })
                continue

        return results

class ClipboardListener(QObject):
    links_detected = Signal(list)
    enabled_changed = Signal(bool)

    def __init__(self, parent=None, initial_enabled: bool = True):
        super().__init__(parent)
        self.enabled = initial_enabled
        self.last_clipboard_text = ""
        self._connected = False

    def start(self):
        clipboard = QApplication.clipboard()
        if clipboard and not self._connected:
            clipboard.dataChanged.connect(self._on_clipboard_changed)
            self._connected = True

    def stop(self):
        clipboard = QApplication.clipboard()
        if clipboard and self._connected:
            try:
                clipboard.dataChanged.disconnect(self._on_clipboard_changed)
            except Exception:
                pass
            self._connected = False

    def toggle(self) -> bool:
        self.enabled = not self.enabled
        self.enabled_changed.emit(self.enabled)
        return self.enabled

    def set_enabled(self, enabled: bool):
        if self.enabled != enabled:
            self.enabled = enabled
            self.enabled_changed.emit(self.enabled)

    def _on_clipboard_changed(self):
        if not self.enabled:
            return

        clipboard = QApplication.clipboard()
        if not clipboard:
            return

        text = clipboard.text()
        if not text:
            return

        clean_text = text.strip()
        # Avoid looping or re-triggering on consecutive identical clipboard events
        if clean_text == self.last_clipboard_text:
            return

        self.last_clipboard_text = clean_text
        detected = ClipboardLinkParser.extract_links(clean_text)
        if detected:
            self.links_detected.emit(detected)
