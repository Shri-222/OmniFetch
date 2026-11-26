"""
OmniFetch Daily Download Queue Scheduler
Handles configurable start/stop time windows (including midnight wrap-around)
to automatically resume queued/paused tasks inside the window and pause active tasks outside.
"""

from datetime import datetime


def _parse_hhmm(hhmm: str, default: tuple[int, int] = (0, 0)) -> tuple[int, int]:
    try:
        parts = str(hhmm).strip().split(":")
        h = max(0, min(23, int(parts[0])))
        m = max(0, min(59, int(parts[1])))
        return h, m
    except Exception:
        return default


def is_within_schedule(start_hhmm: str, stop_hhmm: str, now_dt: datetime | None = None) -> bool:
    """
    Returns True if now_dt (local time) falls within [start_hhmm, stop_hhmm).
    Supports both same-day (09:00 -> 17:00) and overnight wrap-around (23:00 -> 06:00).
    """
    now_dt = now_dt or datetime.now()
    cur_mins = now_dt.hour * 60 + now_dt.minute
    sh, sm = _parse_hhmm(start_hhmm, (0, 0))
    eh, em = _parse_hhmm(stop_hhmm, (6, 0))
    start_mins = sh * 60 + sm
    stop_mins = eh * 60 + em

    if start_mins == stop_mins:
        return True
    if start_mins < stop_mins:
        return start_mins <= cur_mins < stop_mins
    return cur_mins >= start_mins or cur_mins < stop_mins


class DownloadScheduler:
    def __init__(self):
        self._last_in_window: bool | None = None

    def reset(self):
        self._last_in_window = None

    def evaluate_tick(self, engine_manager, config, now_dt: datetime | None = None) -> str | None:
        """
        Evaluates schedule window once. Returns 'RESUMED', 'PAUSED', or None.
        - When entering or inside schedule window (on transition or startup): resumes QUEUED/PAUSED tasks.
        - When exiting schedule window (or disabled while previously inside -> no-op unless active exit):
          pauses active & queued tasks cleanly.
        """
        if not getattr(config, "schedule_enabled", False):
            self._last_in_window = None
            return None

        in_window = is_within_schedule(
            getattr(config, "schedule_start_time", "00:00"),
            getattr(config, "schedule_stop_time", "06:00"),
            now_dt=now_dt,
        )

        action = None
        if in_window and self._last_in_window is not True:
            engine_manager.resume_all()
            action = "RESUMED"
        elif not in_window and self._last_in_window is not False:
            engine_manager.pause_all()
            action = "PAUSED"

        self._last_in_window = in_window
        return action
