"""
OmniFetch Smart Pre-Download Torrent Threat Inspector
Analyzes torrent file-tree metadata BEFORE downloading any payload bytes.
Distinguishes real traps from legitimate game/software installers:
- Auto-Unchecks (CRITICAL TRAP - Red): Double extensions, .scr/.vbs/.hta, small .exe in media torrents.
- Flags Only / Keeps Checked (REVIEW - Amber): Legitimate .exe/.dll/.msi in software/game torrents.
- Clean (Normal - Green): Media, archives, documents.
"""

import os
import re
from pathlib import Path

MEDIA_EXTS = {
    '.mkv', '.mp4', '.avi', '.mov', '.wmv', '.m4v', '.webm',
    '.mp3', '.flac', '.wav', '.aac', '.ogg', '.m4a',
    '.pdf', '.epub', '.mobi', '.cbr', '.cbz',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
    '.srt', '.sub', '.vtt', '.idx', '.nfo', '.txt'
}

PRIMARY_MEDIA_EXTS = {
    '.mkv', '.mp4', '.avi', '.mov', '.wmv', '.m4v', '.webm',
    '.mp3', '.flac', '.wav', '.aac', '.ogg', '.m4a',
    '.pdf', '.epub', '.mobi', '.cbr', '.cbz'
}

SOFTWARE_GAME_EXTS = {
    '.exe', '.msi', '.dll', '.iso', '.bin', '.cue', '.vmdk', '.img'
}

EXEC_EXTS = {
    '.exe', '.dll', '.msi', '.bat', '.cmd', '.scr',
    '.pif', '.vbs', '.hta', '.lnk', '.jse', '.ps1'
}

DANGEROUS_SCRIPT_EXTS = {
    '.scr', '.pif', '.vbs', '.hta', '.lnk', '.jse'
}

DOUBLE_EXT_PATTERN = re.compile(
    r'\.(mp4|mkv|avi|mov|mp3|flac|pdf|txt|jpg|png|doc|docx|zip)\.(exe|scr|bat|cmd|vbs|pif|hta|lnk|jse)$',
    re.IGNORECASE
)

class TorrentFileInspector:
    @staticmethod
    def inspect_file_tree(files):
        """
        Takes a list of file dictionaries: [{'index': int, 'path': str, 'size': int}, ...]
        Returns enriched file list with:
        - checked: bool (True = download, False = skip)
        - priority: int (0 = skip, 4 = normal, 7 = high)
        - severity: str ('CLEAN', 'LOW', 'CRITICAL')
        - badge: str
        - reason: str
        """
        if not files:
            return {
                "context": "UNKNOWN",
                "files": [],
                "trap_count": 0,
                "review_count": 0,
                "clean_count": 0
            }

        # 1. Determine Torrent Context (Media vs Software/Game)
        total_size = sum(f.get('size', 0) for f in files)
        primary_media_size = 0
        software_size = 0
        has_large_installer = False

        for f in files:
            path_str = f.get('path', '')
            ext = os.path.splitext(path_str)[1].lower()
            sz = f.get('size', 0)
            if ext in PRIMARY_MEDIA_EXTS:
                primary_media_size += sz
            if ext in SOFTWARE_GAME_EXTS:
                software_size += sz
                if ext in ('.exe', '.msi', '.iso') and sz >= 50 * 1024 * 1024:
                    has_large_installer = True

        # If has a large installer or software assets outweigh media, it's SOFTWARE_OR_GAME
        if has_large_installer or (software_size > 0 and software_size >= primary_media_size):
            context_type = "SOFTWARE_OR_GAME"
        elif total_size > 0 and (primary_media_size / total_size) >= 0.70:
            context_type = "MEDIA"
        elif any(os.path.splitext(f.get('path', ''))[1].lower() in PRIMARY_MEDIA_EXTS for f in files):
            context_type = "MEDIA"
        else:
            context_type = "SOFTWARE_OR_GAME"

        is_media_context = (context_type == "MEDIA")

        # 2. Inspect each file individually
        inspected_files = []
        trap_count = 0
        review_count = 0
        clean_count = 0

        for idx, f in enumerate(files):
            file_index = f.get('index', idx)
            rel_path = f.get('path', '')
            file_size = f.get('size', 0)
            filename = os.path.basename(rel_path)
            ext = os.path.splitext(filename)[1].lower()

            item = {
                "index": file_index,
                "path": rel_path,
                "name": filename,
                "size": file_size,
                "checked": True,
                "priority": 4,  # libtorrent normal priority
                "severity": "CLEAN",
                "badge": "🛡️ Clean",
                "reason": "Normal file"
            }

            # Rule A: Double Extension Masquerade (Always CRITICAL TRAP)
            if DOUBLE_EXT_PATTERN.search(filename):
                item["checked"] = False
                item["priority"] = 0
                item["severity"] = "CRITICAL"
                item["badge"] = "🚨 Critical Trap"
                item["reason"] = f"Deceptive Double extension: {filename}"
                trap_count += 1

            # Rule B: Inherently Dangerous Script/Executable formats (Always CRITICAL TRAP)
            elif ext in DANGEROUS_SCRIPT_EXTS:
                item["checked"] = False
                item["priority"] = 0
                item["severity"] = "CRITICAL"
                item["badge"] = "🚨 Critical Trap"
                item["reason"] = f"Dangerous executable/script format: {ext}"
                trap_count += 1

            # Rule C: Tiny executable (< 5 MB) hidden inside a Media Torrent
            elif is_media_context and ext in ('.exe', '.bat', '.cmd', '.ps1') and file_size < 5 * 1024 * 1024:
                item["checked"] = False
                item["priority"] = 0
                item["severity"] = "CRITICAL"
                item["badge"] = "🚨 Critical Trap"
                item["reason"] = f"Suspicious small executable ({file_size // 1024} KB) in media torrent"
                trap_count += 1

            # Rule D: Legitimate-looking Executables/Installers in Software/Game context
            elif ext in ('.exe', '.dll', '.msi'):
                item["checked"] = True
                item["priority"] = 4
                item["severity"] = "LOW"
                item["badge"] = "⚠️ Review"
                item["reason"] = "Executable / installer asset (will pass Stage 3 scan)"
                review_count += 1

            # Rule E: Scripts in software context
            elif ext in ('.bat', '.cmd', '.ps1'):
                item["checked"] = True
                item["priority"] = 4
                item["severity"] = "LOW"
                item["badge"] = "⚠️ Script"
                item["reason"] = "Automation script (review before running)"
                review_count += 1

            else:
                clean_count += 1

            inspected_files.append(item)

        return {
            "context": context_type,
            "files": inspected_files,
            "trap_count": trap_count,
            "review_count": review_count,
            "clean_count": clean_count
        }

    @staticmethod
    def extract_files_from_torrent_info(ti):
        """
        Extracts raw file dictionaries from libtorrent.torrent_info object.
        """
        files = []
        fs = ti.files()
        for idx in range(fs.num_files()):
            files.append({
                "index": idx,
                "path": fs.file_path(idx),
                "size": fs.file_size(idx)
            })
        return files
