"""
OmniFetch Staging Containment Engine
Enforces Stage 2 containment: All incomplete & unverified downloads live strictly
inside a hidden .staging directory until cleared by the CyberShield Security Gate.
"""

import os
import time
import shutil
import hashlib
from pathlib import Path

class StagingManager:
    def __init__(self, base_staging_dir):
        self.base_staging_dir = Path(base_staging_dir)
        self.base_staging_dir.mkdir(parents=True, exist_ok=True)
        # On Windows, mark .staging folder as hidden if on NTFS
        self._set_hidden(self.base_staging_dir)

    def _set_hidden(self, path):
        if os.name == 'nt' and path.exists():
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass

    def allocate_task_staging(self, task_id):
        task_dir = self.base_staging_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        return task_dir

    def get_segment_path(self, task_id, segment_index):
        task_dir = self.allocate_task_staging(task_id)
        return task_dir / f"segment_{segment_index}.part"

    def get_staged_file_path(self, task_id, filename):
        task_dir = self.allocate_task_staging(task_id)
        return task_dir / filename

    def get_meta_torrent_path(self, task_id):
        task_dir = self.allocate_task_staging(task_id)
        return task_dir / "meta.torrent"

    def get_resume_data_path(self, task_id):
        task_dir = self.allocate_task_staging(task_id)
        return task_dir / "resume.dat"

    def staged_file_exists(self, task_id, filename) -> bool:
        if not filename:
            return False
        return (self.base_staging_dir / task_id / filename).is_file()

    def assemble_segments(self, task_id, filename, num_segments=None, segments_metadata=None):
        """
        Sequentially concatenates all segment_*.part files into the final staged file,
        sorted strictly by start_byte for dynamic in-half splitting.
        Removes temporary parts upon successful assembly.
        """
        task_dir = self.allocate_task_staging(task_id)
        target_path = task_dir / filename

        parts_to_assemble = []
        if segments_metadata:
            # Sort strictly by start_byte to assemble in exact byte-range order
            sorted_segs = sorted(segments_metadata, key=lambda s: s.get("start_byte", s.get("start", 0)))
            for seg in sorted_segs:
                idx = seg.get("segment_index", seg.get("index"))
                parts_to_assemble.append(task_dir / f"segment_{idx}.part")
        elif num_segments is not None:
            for idx in range(num_segments):
                parts_to_assemble.append(task_dir / f"segment_{idx}.part")
        else:
            part_files = list(task_dir.glob("segment_*.part"))
            parts_to_assemble = sorted(part_files, key=lambda p: int(p.stem.split("_")[1]) if "_" in p.stem and p.stem.split("_")[1].isdigit() else 0)

        with open(target_path, "wb") as outfile:
            for part_path in parts_to_assemble:
                if not part_path.exists():
                    raise FileNotFoundError(f"Missing segment at {part_path}")
                with open(part_path, "rb") as infile:
                    shutil.copyfileobj(infile, outfile, length=1024 * 1024)

        # Cleanup parts after successful stitching
        for part_path in parts_to_assemble:
            try:
                part_path.unlink()
            except Exception:
                pass

        return str(target_path)

    def compute_sha256(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def move_to_destination(self, staged_path, destination_dir):
        """
        Moves verified clean/warned download from staging to user's destination.
        Handles name collisions safely.
        """
        dest_dir = Path(destination_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        staged = Path(staged_path)
        dest_file = dest_dir / staged.name

        # If file exists, find an available numbered suffix
        if dest_file.exists():
            stem = staged.stem
            suffix = staged.suffix
            counter = 1
            while (dest_dir / f"{stem} ({counter}){suffix}").exists():
                counter += 1
            dest_file = dest_dir / f"{stem} ({counter}){suffix}"

        shutil.move(str(staged), str(dest_file))
        
        # Cleanup task staging dir if empty
        task_dir = staged.parent
        try:
            if task_dir != self.base_staging_dir and not any(task_dir.iterdir()):
                task_dir.rmdir()
        except Exception:
            pass

        return str(dest_file)

    def cleanup_task(self, task_id):
        task_dir = self.base_staging_dir / task_id
        if task_dir.exists():
            try:
                shutil.rmtree(str(task_dir), ignore_errors=True)
            except Exception:
                pass

    def cleanup_orphaned_staging(self, active_task_ids: set[str], min_age_seconds: int = 3600) -> dict:
        """
        Scans .staging/ and removes ONLY subdirectories whose names are NOT in active_task_ids
        and NOT '_metadata_cache', and whose newest mtime exceeds min_age_seconds.
        Returns summary dict: {removed_count, reclaimed_bytes, reclaimed_mb, removed_ids}.
        """
        if not self.base_staging_dir.exists():
            return {"removed_count": 0, "reclaimed_bytes": 0, "reclaimed_mb": 0.0, "removed_ids": []}

        now = time.time()
        removed_ids = []
        reclaimed_bytes = 0
        protected = set(active_task_ids or set()) | {"_metadata_cache"}

        for entry in list(self.base_staging_dir.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name in protected:
                continue

            try:
                newest_mtime = entry.stat().st_mtime
                dir_bytes = 0
                for sub in entry.rglob("*"):
                    try:
                        st = sub.stat()
                        if st.st_mtime > newest_mtime:
                            newest_mtime = st.st_mtime
                        if sub.is_file():
                            dir_bytes += st.st_size
                    except Exception:
                        pass

                age = max(0.0, now - newest_mtime)
                if min_age_seconds > 0 and age < min_age_seconds:
                    continue

                shutil.rmtree(str(entry), ignore_errors=False)
                removed_ids.append(entry.name)
                reclaimed_bytes += dir_bytes
            except Exception:
                pass

        return {
            "removed_count": len(removed_ids),
            "reclaimed_bytes": reclaimed_bytes,
            "reclaimed_mb": round(reclaimed_bytes / (1024 * 1024), 2),
            "removed_ids": removed_ids,
        }
