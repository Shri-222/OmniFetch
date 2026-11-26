"""
OmniFetch Safe Post-Stage-3 Archive Extractor
Supports stdlib .zip / .tar / .tar.gz / .tgz / .tar.bz2 / .tar.xz (plus optional host 7z.exe for .7z/.rar).
Enforces three mandatory guardrails:
1. Never extracts unless Stage 3 CyberShield verdict is strictly CLEAN (MOVED_CLEAN / CLEAN).
2. Strict Zip-Slip & symlink path-traversal protection using os.path.commonpath.
3. Post-extraction CyberShield Stage 3 scan across extracted executables & scripts.
"""

import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

EXECUTABLE_SCRIPT_EXTS = {
    ".exe", ".dll", ".msi", ".bat", ".ps1", ".vbs", ".scr", ".cmd", ".hta", ".pif", ".jse"
}

STDLIB_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
EXTERNAL_7Z_SUFFIXES = (".7z", ".rar")


class ZipSlipError(ValueError):
    """Raised when an archive member attempts path traversal outside destination."""


def _find_host_7z() -> str | None:
    candidates = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return shutil.which("7z") or shutil.which("7za")


def is_supported_archive(file_path: str | Path) -> bool:
    low = str(file_path).lower()
    if low.endswith(STDLIB_ARCHIVE_SUFFIXES):
        return True
    if low.endswith(EXTERNAL_7Z_SUFFIXES) and _find_host_7z():
        return True
    return False


def _validate_member_path(extract_root: Path, member_name: str) -> Path:
    if not member_name or "\x00" in member_name:
        raise ZipSlipError(f"Unsafe archive member name: {member_name!r}")
    norm = member_name.replace("\\", "/")
    if norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":" and norm[0].isalpha()):
        raise ZipSlipError(f"Absolute path blocked in archive member: {member_name}")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ZipSlipError(f"Path traversal ('..') blocked in archive member: {member_name}")

    root_real = os.path.realpath(str(extract_root))
    target_path = extract_root.joinpath(*parts) if parts else extract_root
    target_real = os.path.realpath(str(target_path))
    if os.path.commonpath([root_real, target_real]) != root_real:
        raise ZipSlipError(f"Escaped extraction root blocked: {member_name}")
    return target_path


class SafeArchiveExtractor:
    @staticmethod
    def extract_and_scan(
        archive_path: str | Path,
        stage3_result: dict | None,
        security_gate=None,
        db=None,
        task_id: str | None = None,
        dest_dir: str | Path | None = None,
    ) -> dict:
        """
        Safely extracts archive_path into a subfolder alongside archive_path (or dest_dir)
        ONLY if stage3_result indicates CLEAN.
        """
        src = Path(archive_path)
        if not src.is_file():
            return {"extracted": False, "reason": "Archive file not found"}

        # Guardrail 1: STRICT Stage 3 CLEAN verdict check
        res = stage3_result or {}
        action = str(res.get("action") or "")
        severity = str(res.get("severity") or "")
        sec_status = str(res.get("security_status") or "")
        status = str(res.get("status") or "")

        is_clean = (
            action == "MOVED_CLEAN"
            or (sec_status == "CLEAN" and status == "COMPLETED")
            or (severity == "CLEAN" and action not in ("QUARANTINED", "SCAN_ERROR", "MOVED_WARNING"))
        )
        if not is_clean:
            return {
                "extracted": False,
                "reason": f"Blocked by Stage 3 Security Policy (action={action or status}, severity={severity or sec_status})",
            }

        low = src.name.lower()
        folder_stem = src.name
        for suf in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz", ".zip", ".tar", ".7z", ".rar"):
            if low.endswith(suf):
                folder_stem = src.name[: -len(suf)]
                break
        base_parent = Path(dest_dir) if dest_dir else src.parent
        extract_root = base_parent / (folder_stem or f"{src.stem}_extracted")
        extract_root.mkdir(parents=True, exist_ok=True)

        extracted_files: list[Path] = []

        # Guardrail 2: Strict Zip-Slip validation + safe extraction
        if low.endswith(".zip"):
            with zipfile.ZipFile(src, "r") as zf:
                infos = zf.infolist()
                for info in infos:
                    if info.is_dir() or info.filename.endswith("/"):
                        _validate_member_path(extract_root, info.filename)
                        continue
                    # Reject symlinks stored in zip external_attr (POSIX S_IFLNK = 0o120000)
                    unix_mode = (info.external_attr >> 16) & 0o170000
                    if unix_mode == 0o120000:
                        raise ZipSlipError(f"Symlink blocked inside zip archive: {info.filename}")
                    target = _validate_member_path(extract_root, info.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as fin, open(target, "wb") as fout:
                        shutil.copyfileobj(fin, fout, length=256 * 1024)
                    extracted_files.append(target)

        elif low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
            with tarfile.open(src, "r:*") as tf:
                members = tf.getmembers()
                for member in members:
                    if member.issym() or member.islnk():
                        raise ZipSlipError(f"Link blocked inside tar archive: {member.name}")
                    target = _validate_member_path(extract_root, member.name)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isfile():
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f_in = tf.extractfile(member)
                    if f_in is not None:
                        with f_in, open(target, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out, length=256 * 1024)
                        extracted_files.append(target)

        elif low.endswith(EXTERNAL_7Z_SUFFIXES):
            seven_z = _find_host_7z()
            if not seven_z:
                return {"extracted": False, "reason": "No local 7-Zip installation found for .7z/.rar"}
            # Validate member listing first via `7z l -slt` before extracting
            list_proc = subprocess.run(
                [seven_z, "l", "-slt", str(src)],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if list_proc.returncode == 0:
                for line in list_proc.stdout.splitlines():
                    if line.startswith("Path = "):
                        rel = line.split("Path = ", 1)[1].strip()
                        if rel and rel != str(src):
                            _validate_member_path(extract_root, rel)
            proc = subprocess.run(
                [seven_z, "x", "-y", f"-o{extract_root}", str(src)],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"7z extraction failed: {(proc.stderr or proc.stdout).strip()[:200]}")
            extracted_files = [p for p in extract_root.rglob("*") if p.is_file()]
        else:
            return {"extracted": False, "reason": f"Unsupported archive format: {src.suffix}"}

        # Guardrail 3: Post-extraction Stage 3 scan of extracted executables & scripts
        quarantined_files = []
        warning_files = []
        scan_error_files = []

        if security_gate is not None:
            for fp in extracted_files:
                if fp.suffix.lower() not in EXECUTABLE_SCRIPT_EXTS:
                    continue
                scan_res = security_gate.bridge.scan_file(str(fp))
                verdict = scan_res.get("verdict", "SCAN_ERROR")
                threat_name = scan_res.get("threatName")
                details = scan_res.get("details", "")

                if db and task_id and verdict in ("BLOCK_CRITICAL", "ALLOW_WARNING", "ALLOW_CLEAN"):
                    try:
                        db.record_security_audit(
                            task_id=task_id,
                            stage="POST_DOWNLOAD",
                            verdict=verdict,
                            threat_name=threat_name,
                            details=f"[Extracted: {fp.name}] {details}",
                        )
                    except Exception:
                        pass

                if verdict == "BLOCK_CRITICAL":
                    security_gate.bridge.quarantine_file(str(fp), threat_name or "ArchiveThreat.Generic", details)
                    # Guarantee unencrypted extracted payload does not remain on disk if vault copied instead of moved
                    if fp.exists():
                        try:
                            fp.unlink()
                        except Exception:
                            pass
                    quarantined_files.append(str(fp))
                elif verdict == "ALLOW_WARNING":
                    warning_files.append(str(fp))
                elif verdict != "ALLOW_CLEAN":
                    # Fail-closed: remove unverified executable if scanner failed
                    if fp.exists():
                        try:
                            fp.unlink()
                        except Exception:
                            pass
                    scan_error_files.append(str(fp))

        return {
            "extracted": True,
            "extract_dir": str(extract_root),
            "extracted_count": len(extracted_files),
            "quarantined_files": quarantined_files,
            "warning_files": warning_files,
            "scan_error_files": scan_error_files,
        }
