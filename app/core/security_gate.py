"""
OmniFetch 3-Stage CyberShield Security Gate
Orchestrates:
- Stage 1 (Pre-Download): Fast URL & filename evaluation (trap detection).
- Stage 2 (Staging Containment): Managed via StagingManager.
- Stage 3 (Post-Download Gate): Real PE heuristics + Microsoft-signed MpCmdRun -DisableRemediation
  with 3-Tier Filter routing:
  * CRITICAL -> Reversible Quarantine Vault (AES-256)
  * LOW -> Move to destination with amber warning badge
  * CLEAN -> Move to destination with clean completion badge
"""

import re
from pathlib import Path
from urllib.parse import urlparse, unquote
from ..integrations.cybershield_bridge import CyberShieldBridge

_SEVERITY_RANK = {
    "CLEAN": 0,
    "LOW": 1,
    "WARNING": 1,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 2,
}


class SecurityGate:
    def __init__(self, cybershield_root=None, db=None, staging_manager=None):
        self.bridge = CyberShieldBridge(cybershield_root) if cybershield_root else CyberShieldBridge()
        self.db = db
        self.staging_manager = staging_manager

    def _match_offline_signatures(self, url: str, filename: str) -> dict | None:
        """Evaluates URL and filename against CyberShield's read-only threat_signatures table."""
        signatures = self.bridge.query_threat_signatures_readonly()
        if not signatures:
            return None

        url_str = url or ""
        name_str = filename or ""
        url_leaf = ""
        try:
            url_leaf = unquote(urlparse(url_str).path or "").split("/")[-1]
        except Exception:
            pass

        best = None
        for sig in signatures:
            sig_type = (sig.get("type") or "").lower()
            pattern = sig.get("pattern") or ""
            sev_raw = (sig.get("severity") or "LOW").upper()
            if not pattern:
                continue

            matched = False
            if sig_type == "filename_regex":
                try:
                    rx = re.compile(pattern, re.IGNORECASE)
                    if (name_str and rx.search(name_str)) or (url_leaf and rx.search(url_leaf)):
                        matched = True
                except re.error:
                    pass
            elif sig_type == "url_regex":
                try:
                    rx = re.compile(pattern, re.IGNORECASE)
                    if url_str and rx.search(url_str):
                        matched = True
                except re.error:
                    pass
            elif sig_type in ("binary_pattern", "url_pattern", "string"):
                # Match non-trivial literal signature tokens present in URL or filename
                if len(pattern) >= 5 and ";" not in pattern:
                    low_pat = pattern.lower()
                    if low_pat in name_str.lower() or low_pat in url_str.lower():
                        matched = True

            if matched:
                if best is None or _SEVERITY_RANK.get(sev_raw, 0) > _SEVERITY_RANK.get(best["severity"], 0):
                    is_crit = _SEVERITY_RANK.get(sev_raw, 0) >= 2
                    best = {
                        "verdict": "BLOCK_CRITICAL" if is_crit else "ALLOW_WARNING",
                        "severity": "CRITICAL" if is_crit else "LOW",
                        "threat_name": sig.get("name"),
                        "details": f"[{sig.get('id')}] {sig.get('description') or sig.get('name')}",
                        "signature_id": sig.get("id"),
                    }
        return best

    def evaluate_pre_download(self, url, filename):
        """
        Stage 1: Check before downloading using both CyberShield metadata heuristics
        and CyberShield's read-only offline_engine.db threat_signatures table.
        """
        res = self.bridge.check_metadata(url, filename)
        verdict = res.get("verdict", "ALLOW_CLEAN")
        severity = res.get("severity", "CLEAN")
        threat_name = res.get("threatName")
        details = res.get("details", "")
        signature_id = None

        db_match = self._match_offline_signatures(url, filename)
        if db_match:
            if _SEVERITY_RANK.get(db_match["severity"], 0) >= _SEVERITY_RANK.get(severity, 0):
                verdict = db_match["verdict"]
                severity = db_match["severity"]
                threat_name = db_match["threat_name"] or threat_name
                details = db_match["details"]
                signature_id = db_match["signature_id"]

        return {
            "allowed": verdict != "BLOCK_CRITICAL",
            "verdict": verdict,
            "severity": severity,
            "threat_name": threat_name,
            "details": details,
            "signature_id": signature_id,
        }

    def evaluate_post_download(self, task_id, staged_file_path, destination_dir):
        """
        Stage 3: Full inspection of staged file before allowing it into user folders.
        """
        staged = Path(staged_file_path)
        if not staged.exists():
            return {
                "action": "ERROR",
                "verdict": "FAILED",
                "error": f"Staged file not found: {staged_file_path}"
            }

        scan_result = self.bridge.scan_file(str(staged))
        verdict = scan_result.get("verdict", "SCAN_ERROR")
        severity = scan_result.get("severity", "SCAN_ERROR")
        threat_name = scan_result.get("threatName")
        details = scan_result.get("details", "")

        if verdict in ("BLOCK_CRITICAL", "ALLOW_WARNING", "ALLOW_CLEAN"):
            if self.db and self.db.get_task(task_id):
                self.db.record_security_audit(
                    task_id=task_id,
                    stage="POST_DOWNLOAD",
                    verdict=verdict,
                    threat_name=threat_name,
                    details=details
                )

        if verdict == "BLOCK_CRITICAL":
            # Quarantine the file using CyberShield's AES-256 vault
            q_res = self.bridge.quarantine_file(str(staged), threat_name, details)
            if self.db and self.db.get_task(task_id):
                self.db.update_task_security(task_id, "CRITICAL", threat_name, details)
                self.db.update_task_status(task_id, "QUARANTINED")

            return {
                "action": "QUARANTINED",
                "verdict": "BLOCK_CRITICAL",
                "severity": "CRITICAL",
                "threat_name": threat_name,
                "details": details,
                "quarantine_result": q_res
            }

        elif verdict == "ALLOW_WARNING":
            # Move safely to destination, but tag with warning
            final_path = self.staging_manager.move_to_destination(str(staged), destination_dir) if self.staging_manager else str(staged)
            if self.db and self.db.get_task(task_id):
                self.db.update_task_security(task_id, "WARNING", threat_name, details)
                self.db.update_task_status(task_id, "COMPLETED")

            return {
                "action": "MOVED_WARNING",
                "verdict": "ALLOW_WARNING",
                "severity": "LOW",
                "threat_name": threat_name,
                "details": details,
                "final_path": final_path
            }

        elif verdict == "ALLOW_CLEAN":
            # Clean: Move to destination
            final_path = self.staging_manager.move_to_destination(str(staged), destination_dir) if self.staging_manager else str(staged)
            if self.db and self.db.get_task(task_id):
                self.db.update_task_security(task_id, "CLEAN", None, "No threat signatures detected")
                self.db.update_task_status(task_id, "COMPLETED")

            return {
                "action": "MOVED_CLEAN",
                "verdict": "ALLOW_CLEAN",
                "severity": "CLEAN",
                "threat_name": None,
                "details": "Clean",
                "final_path": final_path
            }

        else:
            # Fail-closed: hold unverified file strictly inside .staging/ and mark FAILED
            err_msg = f"Security scan failed (held in staging): {details}"
            if self.db and self.db.get_task(task_id):
                self.db.update_task_security(task_id, "UNCHECKED", None, f"SCAN_ERROR: {details}")
                self.db.update_task_status(task_id, "FAILED", error_message=err_msg)

            return {
                "action": "SCAN_ERROR",
                "verdict": "SCAN_ERROR",
                "severity": "SCAN_ERROR",
                "threat_name": None,
                "details": details,
                "error": err_msg,
                "staged_path": str(staged)
            }
