"""
OmniFetch Real-Time Speed Graph Widget
A lightweight native QPainter widget tracking 60-second live download and upload speeds.
Zero matplotlib/external dependencies, styled to match the Linear/Fluent dark design.
"""

from collections import deque
from PySide6.QtWidgets import QWidget
from PySide6.QtGui import (
    QPainter, QColor, QPen, QBrush, QLinearGradient, QPainterPath, QFont
)
from PySide6.QtCore import Qt, QPointF

def format_speed(bps: float) -> str:
    if bps >= 1024 * 1024 * 1024:
        return f"{bps / (1024**3):.1f} GB/s"
    if bps >= 1024 * 1024:
        return f"{bps / (1024**2):.1f} MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.0f} KB/s"
    return f"{bps:.0f} B/s"

class SpeedGraphWidget(QWidget):
    def __init__(self, parent=None, history_len: int = 60):
        super().__init__(parent)
        self.history_len = history_len
        self.dl_history = deque([0.0] * history_len, maxlen=history_len)
        self.ul_history = deque([0.0] * history_len, maxlen=history_len)
        self.current_dl = 0.0
        self.current_ul = 0.0
        self.setMinimumHeight(60)
        self.setMaximumHeight(90)
        self.setStyleSheet("background: transparent;")

    def update_speeds(self, dl_bps: float, ul_bps: float = 0.0):
        """Pushes latest speed measurements and triggers repaint."""
        self.current_dl = dl_bps
        self.current_ul = ul_bps
        self.dl_history.append(dl_bps)
        self.ul_history.append(ul_bps)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        w = self.width()
        h = self.height()

        # Background container
        bg_rect = QPainterPath()
        bg_rect.addRoundedRect(1, 1, w - 2, h - 2, 6, 6)
        painter.fillPath(bg_rect, QColor(24, 24, 27))  # #18181b
        painter.strokePath(bg_rect, QPen(QColor(39, 39, 42), 1))  # #27272a

        # Determine dynamic peak scale (at least 1 MB/s ceiling)
        peak = max(max(self.dl_history), max(self.ul_history), 1024 * 1024)

        pad_left = 12
        pad_right = 12
        pad_top = 22
        pad_bottom = 8

        plot_w = w - pad_left - pad_right
        plot_h = h - pad_top - pad_bottom

        if plot_w <= 10 or plot_h <= 10:
            painter.end()
            return

        # Subtle horizontal grid line at 50%
        painter.setPen(QPen(QColor(39, 39, 42, 120), 1, Qt.DashLine))
        mid_y = pad_top + plot_h / 2.0
        painter.drawLine(QPointF(pad_left, mid_y), QPointF(w - pad_right, mid_y))

        # Build Download Path
        step_x = plot_w / float(self.history_len - 1)
        dl_path = QPainterPath()
        dl_fill = QPainterPath()

        dl_fill.moveTo(pad_left, pad_top + plot_h)

        for i, val in enumerate(self.dl_history):
            x = pad_left + i * step_x
            norm = min(1.0, val / peak)
            y = pad_top + plot_h - (norm * plot_h)
            if i == 0:
                dl_path.moveTo(x, y)
            else:
                dl_path.lineTo(x, y)
            dl_fill.lineTo(x, y)

        dl_fill.lineTo(pad_left + (self.history_len - 1) * step_x, pad_top + plot_h)
        dl_fill.closeSubpath()

        # Draw filled gradient under download curve
        grad = QLinearGradient(0, pad_top, 0, pad_top + plot_h)
        grad.setColorAt(0.0, QColor(59, 130, 246, 70))   # blue with transparency
        grad.setColorAt(1.0, QColor(59, 130, 246, 5))
        painter.fillPath(dl_fill, QBrush(grad))

        # Stroke download line
        painter.strokePath(dl_path, QPen(QColor(96, 165, 250), 1.8))

        # Build Upload Path (subtle emerald green)
        ul_path = QPainterPath()
        for i, val in enumerate(self.ul_history):
            x = pad_left + i * step_x
            norm = min(1.0, val / peak)
            y = pad_top + plot_h - (norm * plot_h)
            if i == 0:
                ul_path.moveTo(x, y)
            else:
                ul_path.lineTo(x, y)

        painter.strokePath(ul_path, QPen(QColor(16, 185, 129, 200), 1.2, Qt.DashLine))

        # Header Legend
        font = QFont("Segoe UI", 9)
        painter.setFont(font)

        # Download indicator
        painter.setPen(QColor(96, 165, 250))
        dl_str = f"▼ {format_speed(self.current_dl)}"
        painter.drawText(pad_left + 4, 16, dl_str)

        # Upload indicator
        painter.setPen(QColor(16, 185, 129))
        ul_str = f"▲ {format_speed(self.current_ul)}"
        painter.drawText(pad_left + 110, 16, ul_str)

        # Peak indicator
        painter.setPen(QColor(161, 161, 170))
        peak_str = f"Peak: {format_speed(peak)}"
        painter.drawText(w - pad_right - 90, 16, peak_str)

        painter.end()
