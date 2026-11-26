"""
OmniFetch Download Table Model & Custom Delegates
Renders tasks, monochrome file-type icons, color-coded progress bars,
subtle Status/Security pill badges, interactive sorting, and live structural row updates.
"""

from pathlib import Path
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import QStyledItemDelegate
from PySide6.QtGui import QColor, QBrush, QPen

from .icons import get_icon

COLUMNS = ["File Name", "Size", "Progress", "Speed", "ETA", "Resumable", "Engine", "Status", "Security Gate"]

_VIDEO_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".flv", ".ts", ".m3u8"}
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz", ".iso"}
_PROGRAM_EXTS = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".apk", ".dmg", ".deb", ".rpm"}
_DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".epub", ".md"}
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".avif", ".tiff"}


def format_bytes(num_bytes):
    if num_bytes is None or num_bytes <= 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_eta(seconds):
    if seconds is None or seconds <= 0:
        return "--"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    sec = seconds % 60
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours = minutes // 60
    min_rem = minutes % 60
    return f"{hours}h {min_rem}m"


def get_task_icon_name(task: dict) -> str:
    eng = (task.get("engine_type") or "HTTP").upper()
    if eng == "TORRENT":
        return "torrent"
    if eng == "MEGA":
        return "mega"
    ext = Path(str(task.get("filename") or "")).suffix.lower()
    if ext in _VIDEO_EXTS:
        return "video"
    if ext in _ARCHIVE_EXTS:
        return "archive"
    if ext in _PROGRAM_EXTS:
        return "program"
    if ext in _DOC_EXTS:
        return "document"
    if ext in _IMAGE_EXTS:
        return "image"
    return "file"


class ProgressBarDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        col = index.column()
        if col == 2:
            progress = index.data(Qt.UserRole)
            if progress is None:
                progress = 0

            painter.save()
            painter.setRenderHint(painter.RenderHint.Antialiasing, True)
            bg_rect = option.rect.adjusted(5, 7, -5, -7)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor("#1a1f2e")))
            painter.drawRoundedRect(bg_rect, 5, 5)

            status = str(index.sibling(index.row(), 7).data(Qt.DisplayRole) or "")
            if "QUARANTINED" in status or "FAILED" in status:
                color = QColor("#ef4444")
            elif "COMPLETED" in status:
                color = QColor("#10b981")
            elif "PAUSED" in status or "LINK EXPIRED" in status:
                color = QColor("#f59e0b")
            elif "SCANNING" in status or "STAGED" in status:
                color = QColor("#8b5cf6")
            elif "QUEUED" in status:
                color = QColor("#3b82f6")
            else:
                color = QColor("#06b6d4")

            if progress > 0:
                fill_width = max(6, int(bg_rect.width() * (min(100, progress) / 100.0)))
                fill_rect = bg_rect.adjusted(0, 0, -(bg_rect.width() - fill_width), 0)
                painter.setBrush(QBrush(color))
                painter.drawRoundedRect(fill_rect, 5, 5)

            painter.setPen(QColor("#f9fafb"))
            painter.drawText(option.rect, Qt.AlignCenter, f"{progress}%")
            painter.restore()

        elif col in (7, 8):
            text = str(index.data(Qt.DisplayRole) or "")
            fg = index.data(Qt.ForegroundRole)
            fg_color = fg if isinstance(fg, QColor) else QColor("#9ca3af")

            painter.save()
            painter.setRenderHint(painter.RenderHint.Antialiasing, True)
            if option.state & option.State_Selected:
                painter.fillRect(option.rect, option.palette.highlight())

            pill_rect = option.rect.adjusted(6, 6, -6, -6)
            bg_col = QColor(fg_color)
            bg_col.setAlpha(28)
            border_col = QColor(fg_color)
            border_col.setAlpha(85)

            painter.setPen(QPen(border_col, 1))
            painter.setBrush(QBrush(bg_col))
            painter.drawRoundedRect(pill_rect, 8, 8)

            painter.setPen(fg_color)
            elided = option.fontMetrics.elidedText(text, Qt.ElideRight, max(20, pill_rect.width() - 12))
            painter.drawText(pill_rect, Qt.AlignCenter, elided)
            painter.restore()
        else:
            super().paint(painter, option, index)


class DownloadTableModel(QAbstractTableModel):
    def __init__(self, tasks=None):
        super().__init__()
        self.tasks = tasks or []
        self._sort_column = -1
        self._sort_order = Qt.DescendingOrder
        self._icon_cache = {}

    def rowCount(self, parent=QModelIndex()):
        return len(self.tasks)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def _get_cached_icon(self, name: str):
        if name not in self._icon_cache:
            color_map = {
                "torrent": "#34d399",
                "mega": "#f87171",
                "video": "#38bdf8",
                "archive": "#fbbf24",
                "program": "#a78bfa",
                "document": "#60a5fa",
                "image": "#f472b6",
                "file": "#9ca3af",
            }
            self._icon_cache[name] = get_icon(name, color=color_map.get(name, "#d4d4d8"), size=16)
        return self._icon_cache[name]

    def _sort_key(self, task: dict, col: int):
        if col == 0:
            return str(task.get("filename") or "").lower()
        if col == 1:
            return int(task.get("total_bytes") or 0)
        if col == 2:
            tot = task.get("total_bytes") or 0
            cur = task.get("downloaded_bytes") or 0
            return (cur / tot) if tot > 0 else 0.0
        if col == 3:
            return float(task.get("speed_bps") or 0.0) if task.get("status") == "DOWNLOADING" else 0.0
        if col == 4:
            return int(task.get("eta_seconds") or 0) if task.get("status") == "DOWNLOADING" else 10**9
        if col == 5:
            return int(task.get("resumable") if task.get("resumable") is not None else -1)
        if col == 6:
            return str(task.get("engine_type") or "")
        if col == 7:
            return str(task.get("status") or "")
        if col == 8:
            return str(task.get("security_status") or "")
        return float(task.get("created_at") or 0.0)

    def _apply_sort(self, tasks: list[dict]) -> list[dict]:
        copied = [dict(t) for t in tasks]
        if 0 <= self._sort_column < len(COLUMNS):
            copied.sort(
                key=lambda t: self._sort_key(t, self._sort_column),
                reverse=(self._sort_order == Qt.DescendingOrder),
            )
        return copied

    def sort(self, column: int, order=Qt.AscendingOrder):
        self._sort_column = column
        self._sort_order = order
        if not self.tasks:
            return
        self.update_tasks(self.tasks)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.tasks):
            return None

        task = self.tasks[index.row()]
        col = index.column()

        if role == Qt.DecorationRole and col == 0:
            return self._get_cached_icon(get_task_icon_name(task))

        if role == Qt.DisplayRole:
            if col == 0:
                return task.get("filename", "")
            elif col == 1:
                cur = format_bytes(task.get("downloaded_bytes", 0))
                tot_b = task.get("total_bytes", 0)
                tot = format_bytes(tot_b) if tot_b > 0 else "Unknown"
                return f"{cur} / {tot}"
            elif col == 2:
                tot = task.get("total_bytes", 0)
                cur = task.get("downloaded_bytes", 0)
                pct = int((cur / tot) * 100) if tot > 0 else 0
                return f"{pct}%"
            elif col == 3:
                if task.get("status") != "DOWNLOADING":
                    return "--"
                speed = task.get("speed_bps", 0.0)
                return f"{format_bytes(speed)}/s" if speed > 0 else "--"
            elif col == 4:
                if task.get("status") != "DOWNLOADING":
                    return "--"
                return format_eta(task.get("eta_seconds", 0))
            elif col == 5:
                resumable = task.get("resumable", -1)
                if resumable == 1:
                    return "Yes"
                elif resumable == 0:
                    return "No"
                return "Checking"
            elif col == 6:
                return task.get("engine_type", "HTTP")
            elif col == 7:
                st = task.get("status", "QUEUED")
                err = task.get("error_message")
                if st == "FAILED" and err:
                    short_err = err[:24] + "..." if len(err) > 24 else err
                    return f"FAILED ({short_err})"
                return st
            elif col == 8:
                st = task.get("status", "QUEUED")
                sec = task.get("security_status", "UNCHECKED")

                if sec == "CRITICAL" or st == "QUARANTINED":
                    return "Quarantined"

                if st == "FAILED" and str(task.get("threat_details") or "").startswith("SCAN_ERROR:"):
                    return "Scan Error"

                if st == "COMPLETED":
                    if sec == "CLEAN":
                        return "Clean"
                    elif sec == "WARNING":
                        return "Low Warning"
                    return "Not Scanned"

                if st in ("QUEUED", "DOWNLOADING", "STAGED", "SCANNING"):
                    return "Pending"

                return "Not Scanned"

        elif role == Qt.ToolTipRole:
            err = task.get("error_message")
            fn = task.get("filename", "")
            url = task.get("url", "")
            if err:
                return f"Task #{task.get('id')} — FAILED\nFile: {fn}\nError: {err}\nURL: {url}"
            return f"Task #{task.get('id')}\nFile: {fn}\nURL: {url}\nDestination: {task.get('destination')}"

        elif role == Qt.UserRole and col == 2:
            tot = task.get("total_bytes", 0)
            cur = task.get("downloaded_bytes", 0)
            return int((cur / tot) * 100) if tot > 0 else 0

        elif role == Qt.ForegroundRole:
            if col == 5:
                resumable = task.get("resumable", -1)
                if resumable == 1:
                    return QColor("#10b981")
                elif resumable == 0:
                    return QColor("#f59e0b")
                return QColor("#9ca3af")
            elif col == 7:
                st = task.get("status", "")
                if st == "COMPLETED":
                    return QColor("#10b981")
                elif st == "DOWNLOADING":
                    return QColor("#06b6d4")
                elif st in ("SCANNING", "STAGED"):
                    return QColor("#a78bfa")
                elif st == "QUEUED":
                    return QColor("#60a5fa")
                elif st in ("PAUSED", "LINK EXPIRED"):
                    return QColor("#f59e0b")
                elif st == "QUARANTINED" or st == "FAILED":
                    return QColor("#ef4444")
            elif col == 8:
                st = task.get("status", "")
                sec = task.get("security_status", "")
                if sec == "CRITICAL" or st == "QUARANTINED":
                    return QColor("#ef4444")
                if st == "FAILED" and str(task.get("threat_details") or "").startswith("SCAN_ERROR:"):
                    return QColor("#ef4444")
                if st == "COMPLETED":
                    if sec == "CLEAN":
                        return QColor("#10b981")
                    elif sec == "WARNING":
                        return QColor("#f59e0b")
                    return QColor("#9ca3af")
                if st in ("QUEUED", "DOWNLOADING", "STAGED", "SCANNING"):
                    return QColor("#06b6d4")
                return QColor("#9ca3af")

        return None

    def update_tasks(self, tasks):
        sorted_tasks = self._apply_sort(tasks)
        old_ids = [t.get("id") for t in self.tasks]
        new_ids = [t.get("id") for t in sorted_tasks]
        last_col = len(COLUMNS) - 1

        # Case 1: Identical ID order -> update changed rows in place
        if old_ids == new_ids:
            for row, (old_task, new_task) in enumerate(zip(self.tasks, sorted_tasks)):
                if old_task != new_task:
                    self.tasks[row] = dict(new_task)
                    self.dataChanged.emit(self.index(row, 0), self.index(row, last_col))
            return

        old_set = set(old_ids)
        new_set = set(new_ids)

        # Case 2: Pure insertions (all old IDs kept in identical relative order)
        if old_ids == [nid for nid in new_ids if nid in old_set] and len(new_ids) > len(old_ids):
            pos = 0
            while pos < len(sorted_tasks):
                nid = sorted_tasks[pos].get("id")
                if pos < len(self.tasks) and self.tasks[pos].get("id") == nid:
                    if self.tasks[pos] != sorted_tasks[pos]:
                        self.tasks[pos] = dict(sorted_tasks[pos])
                        self.dataChanged.emit(self.index(pos, 0), self.index(pos, last_col))
                    pos += 1
                else:
                    end = pos
                    while end < len(sorted_tasks) and sorted_tasks[end].get("id") not in old_set:
                        end += 1
                    self.beginInsertRows(QModelIndex(), pos, end - 1)
                    for k in range(pos, end):
                        self.tasks.insert(k, dict(sorted_tasks[k]))
                    self.endInsertRows()
                    pos = end
            return

        # Case 3: Pure deletions (all new IDs existed in old_ids in identical relative order)
        if new_ids == [oid for oid in old_ids if oid in new_set] and len(new_ids) < len(old_ids):
            row = len(self.tasks) - 1
            while row >= 0:
                oid = self.tasks[row].get("id")
                if oid not in new_set:
                    self.beginRemoveRows(QModelIndex(), row, row)
                    self.tasks.pop(row)
                    self.endRemoveRows()
                row -= 1
            for r, (old_task, new_task) in enumerate(zip(self.tasks, sorted_tasks)):
                if old_task != new_task:
                    self.tasks[r] = dict(new_task)
                    self.dataChanged.emit(self.index(r, 0), self.index(r, last_col))
            return

        # Case 4: General reorder/sort/filter switch -> layoutChanged preserving persistent indexes
        self.layoutAboutToBeChanged.emit()
        old_pers = self.persistentIndexList()
        old_id_by_row = {r: t.get("id") for r, t in enumerate(self.tasks)}
        new_row_by_id = {t.get("id"): r for r, t in enumerate(sorted_tasks)}

        self.tasks = sorted_tasks
        new_pers = []
        for idx in old_pers:
            tid = old_id_by_row.get(idx.row())
            if tid in new_row_by_id:
                new_pers.append(self.index(new_row_by_id[tid], idx.column()))
            else:
                new_pers.append(QModelIndex())
        if old_pers:
            self.changePersistentIndexList(old_pers, new_pers)
        self.layoutChanged.emit()

    def update_task_progress(self, task_id, downloaded, total, speed, eta):
        for row, task in enumerate(self.tasks):
            if task.get("id") == task_id:
                task["downloaded_bytes"] = downloaded
                task["total_bytes"] = total
                task["speed_bps"] = speed
                task["eta_seconds"] = eta
                self.dataChanged.emit(self.index(row, 1), self.index(row, 4))
                return True
        return False

    def update_task_status(self, task_id, status):
        for row, task in enumerate(self.tasks):
            if task.get("id") == task_id:
                task["status"] = status
                self.dataChanged.emit(self.index(row, 2), self.index(row, 8))
                return True
        return False
