"""
OmniFetch CyberShield Safe Integration Bridge
Invokes CyberShield's JavaScript engines via node.exe CLI wrapper and reads SQLite in read-only mode (?mode=ro).
STRICT ZERO-MUTATION GUARANTEE: Never alters any file inside C:\\Users\\shrey\\Desktop\\CyberShield.
"""

import os
import sys
import json
import sqlite3
import shutil
import subprocess
from pathlib import Path
from ..core.config import get_resource_path

DEFAULT_CYBERSHIELD_ROOT = r"C:\Users\shrey\Desktop\CyberShield"

class CyberShieldBridge:
    def __init__(self, cybershield_root=DEFAULT_CYBERSHIELD_ROOT):
        self.cybershield_root = Path(cybershield_root)
        self.cli_wrapper = get_resource_path("app/integrations/cybershield_cli.js")
        if not self.cli_wrapper.exists():
            self.cli_wrapper = Path(__file__).parent / "cybershield_cli.js"
        self.node_exe = self._resolve_node()
        self.db_path = self.cybershield_root / "data" / "offline_engine.db"

    def _resolve_node(self):
        found = shutil.which("node")
        if found:
            return found
        standard_paths = [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe"
        ]
        for p in standard_paths:
            if os.path.exists(p):
                return p
        return "node"

    def is_available(self):
        return (
            self.cybershield_root.exists() and
            self.cli_wrapper.exists() and
            os.path.exists(self.node_exe) if os.path.isabs(self.node_exe) else True
        )

    def query_threat_signatures_readonly(self):
        """
        Direct read-only SQLite query to CyberShield's offline database using ?mode=ro URI.
        """
        if not self.db_path.exists():
            return []

        try:
            uri = f"file:{self.db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, severity, type, pattern, description FROM threat_signatures;")
            rows = cursor.fetchall()
            conn.close()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "severity": r[2],
                    "type": r[3],
                    "pattern": r[4],
                    "description": r[5]
                }
                for r in rows
            ]
        except Exception:
            return []

    def check_metadata(self, url, filename):
        """
        Stage 1 Pre-Download Metadata Check:
        Detects camouflage double-extensions and known suspicious patterns.
        """
        env = os.environ.copy()
        env["CYBERSHIELD_ROOT"] = str(self.cybershield_root)

        try:
            proc = subprocess.run(
                [self.node_exe, str(self.cli_wrapper), "check-metadata", url or "", filename or ""],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if proc.returncode == 0 and proc.stdout:
                return json.loads(proc.stdout.strip())
        except Exception as e:
            pass

        # Fallback local metadata evaluation if Node fails
        lower_name = (filename or "").lower()
        if any(lower_name.endswith(ext) for ext in [".exe", ".scr", ".bat", ".cmd", ".vbs"]):
            is_double = any(f".{x}." in lower_name for x in ["pdf", "doc", "docx", "jpg", "png", "mp4", "zip", "txt"])
            if is_double:
                return {
                    "verdict": "BLOCK_CRITICAL",
                    "severity": "CRITICAL",
                    "threatName": "Exploit.DoubleExtension",
                    "details": f"Deceptive double extension detected: {filename}"
                }
            return {
                "verdict": "ALLOW_WARNING",
                "severity": "LOW",
                "threatName": "PotentiallyUnwanted.Executable",
                "details": f"Executable file: {filename}"
            }

        return {
            "verdict": "ALLOW_CLEAN",
            "severity": "CLEAN",
            "threatName": None,
            "details": "Metadata check passed"
        }

    def scan_file(self, file_path):
        """
        Stage 3 Post-Download Scan:
        Executes CyberShield PE Heuristics and Microsoft-signed MpCmdRun -DisableRemediation
        via our Node.js CLI wrapper.
        Strictly FAIL-CLOSED: any missing executable, timeout, crash, or parse failure
        returns verdict='SCAN_ERROR' so unverified payloads remain isolated in .staging/.
        """
        env = os.environ.copy()
        env["CYBERSHIELD_ROOT"] = str(self.cybershield_root)

        try:
            proc = subprocess.run(
                [self.node_exe, str(self.cli_wrapper), "scan", str(file_path)],
                capture_output=True,
                text=True,
                timeout=180,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if proc.returncode == 0 and proc.stdout and proc.stdout.strip():
                parsed = json.loads(proc.stdout.strip())
                if isinstance(parsed, dict) and parsed.get("verdict") in ("ALLOW_CLEAN", "ALLOW_WARNING", "BLOCK_CRITICAL"):
                    return parsed
                return {
                    "verdict": "SCAN_ERROR",
                    "severity": "SCAN_ERROR",
                    "threatName": None,
                    "details": f"Invalid scan output schema: {proc.stdout[:200]}",
                    "detections": []
                }
            return {
                "verdict": "SCAN_ERROR",
                "severity": "SCAN_ERROR",
                "threatName": None,
                "details": f"Scan returned non-zero ({proc.returncode}): {(proc.stderr or proc.stdout or '').strip()[:250]}",
                "detections": []
            }
        except Exception as e:
            return {
                "verdict": "SCAN_ERROR",
                "severity": "SCAN_ERROR",
                "threatName": None,
                "details": f"Scan execution exception: {str(e)}",
                "detections": []
            }

    def quarantine_file(self, file_path, threat_name, details=""):
        """
        Sends critical threat into CyberShield's AES-256 Quarantine Vault.
        """
        env = os.environ.copy()
        env["CYBERSHIELD_ROOT"] = str(self.cybershield_root)

        try:
            proc = subprocess.run(
                [
                    self.node_exe,
                    str(self.cli_wrapper),
                    "quarantine",
                    str(file_path),
                    str(threat_name or "Threat.Generic"),
                    str(details or ""),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if proc.returncode == 0 and proc.stdout:
                return json.loads(proc.stdout.strip())
        except Exception as e:
            return {"success": False, "error": str(e)}

        return {"success": False, "error": "Unknown quarantine error"}
