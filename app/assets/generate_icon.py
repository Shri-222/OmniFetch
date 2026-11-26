"""
Generates crisp multi-resolution icon for OmniFetch
Creates app/assets/omnifetch.ico and app/assets/omnifetch.png
"""

import os
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPixmap, QPainter, QColor, QPen, QBrush, QLinearGradient, QPainterPath
from PySide6.QtCore import Qt, QPointF

def generate_icons():
    app = QApplication.instance() or QApplication([])

    assets_dir = Path(__file__).resolve().parent
    assets_dir.mkdir(parents=True, exist_ok=True)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    pixmaps = []

    for sz in sizes:
        pix = QPixmap(sz, sz)
        pix.fill(QColor(0, 0, 0, 0))

        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

        margin = max(1, sz * 0.05)
        rect_sz = sz - margin * 2

        # Background squircle
        grad = QLinearGradient(0, 0, sz, sz)
        grad.setColorAt(0.0, QColor(24, 24, 27))
        grad.setColorAt(1.0, QColor(9, 9, 11))

        border_pen = QPen(QColor(59, 130, 246, 220), max(1.0, sz * 0.04))
        painter.setPen(border_pen)
        painter.setBrush(QBrush(grad))

        round_rad = sz * 0.22
        painter.drawRoundedRect(margin, margin, rect_sz, rect_sz, round_rad, round_rad)

        # Foreground glyph: Modern Fetch Arrow & Speed Arc
        glyph_pen = QPen(QColor(96, 165, 250), max(1.0, sz * 0.08))
        glyph_pen.setCapStyle(Qt.RoundCap)
        glyph_pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(glyph_pen)
        painter.setBrush(Qt.NoBrush)

        cx = sz / 2.0
        cy = sz / 2.0

        # Vertical stem
        stem_top = cy - sz * 0.22
        stem_bot = cy + sz * 0.16
        painter.drawLine(QPointF(cx, stem_top), QPointF(cx, stem_bot))

        # Arrowhead
        arrow_w = sz * 0.18
        arrow_h = sz * 0.16
        path = QPainterPath()
        path.moveTo(cx - arrow_w, stem_bot - arrow_h)
        path.lineTo(cx, stem_bot)
        path.lineTo(cx + arrow_w, stem_bot - arrow_h)
        painter.drawPath(path)

        # Base tray curve
        tray_y = cy + sz * 0.28
        tray_w = sz * 0.24
        painter.drawLine(QPointF(cx - tray_w, tray_y), QPointF(cx + tray_w, tray_y))

        painter.end()
        pixmaps.append(pix)

    # Save highest res PNG
    png_path = assets_dir / "omnifetch.png"
    pixmaps[-1].save(str(png_path), "PNG")

    # Save multi-res ICO using Qt ICO format or highest res
    ico_path = assets_dir / "omnifetch.ico"
    pixmaps[-1].save(str(ico_path), "ICO")

    print(f"Generated {ico_path} and {png_path}")

if __name__ == "__main__":
    generate_icons()
