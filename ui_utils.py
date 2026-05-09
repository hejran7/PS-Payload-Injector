
import os, sys, ctypes, ctypes.wintypes
import threading
try:
    import winsound as _winsound
except ImportError:
    _winsound = None


def _beep():
    if _winsound is not None:
        _winsound.MessageBeep(_winsound.MB_OK)
from PySide6.QtWidgets import QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QFrame
from PySide6.QtCore import Qt, QTimer, QPoint, Signal
from PySide6.QtGui import QFont, QPainter, QPen, QColor, QCursor
from config import BG_MAIN, ACCENT_RED, ACCENT_GRAY, BG_LIST, BASE_DIR


def _hex_adjust(hex_color: str, factor: float) -> str:
    h = hex_color.lstrip('#')
    r = min(255, max(0, int(int(h[0:2], 16) * factor)))
    g = min(255, max(0, int(int(h[2:4], 16) * factor)))
    b = min(255, max(0, int(int(h[4:6], 16) * factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


def _bevel_qss(bg: str, fg: str, size: str, hover_bg: str = None) -> str:
    hbg  = hover_bg or bg
    hi   = _hex_adjust(bg,  1.5)
    sh   = _hex_adjust(bg,  0.55)
    face = bg
    prs  = _hex_adjust(bg,  0.85)
    h_hi = _hex_adjust(hbg, 1.5)
    h_sh = _hex_adjust(hbg, 0.55)
    dis_hi = _hex_adjust(ACCENT_GRAY, 1.4)
    dis_sh = _hex_adjust(ACCENT_GRAY, 0.6)
    return f"""
        QPushButton {{
            background-color: {face};
            color: {fg};
            font: {size} 'Segoe UI';
            border-top:    1px solid {hi};
            border-left:   1px solid {hi};
            border-bottom: 1px solid {sh};
            border-right:  1px solid {sh};
            padding: 0 4px;
            text-align: center;
        }}
        QPushButton:hover {{
            background-color: {hbg};
            border-top:    1px solid {h_hi};
            border-left:   1px solid {h_hi};
            border-bottom: 1px solid {h_sh};
            border-right:  1px solid {h_sh};
        }}
        QPushButton:pressed {{
            background-color: {prs};
            border-top:    1px solid {sh};
            border-left:   1px solid {sh};
            border-bottom: 1px solid {hi};
            border-right:  1px solid {hi};
            padding-top: 1px; padding-left: 9px;
        }}
        QPushButton:disabled {{
            background-color: {ACCENT_GRAY};
            color: #555566;
            border-top:    1px solid {dis_hi};
            border-left:   1px solid {dis_hi};
            border-bottom: 1px solid {dis_sh};
            border-right:  1px solid {dis_sh};
        }}
    """


class ChevronButton(QFrame):
    clicked = Signal()

    def __init__(self, bg: str = "#0a1628", hover_bg: str = "#1e2d4a",
                 arrow_color: str = "#999999", parent=None):
        super().__init__(parent)
        self._bg       = bg
        self._hover_bg = hover_bg
        self._arrow_color = arrow_color
        self._hover    = False
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setStyleSheet(f"background-color: {bg}; border: none;")

    def enterEvent(self, event):
        self._hover = True
        self.setStyleSheet(f"background-color: {self._hover_bg}; border: none;")
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover = False
        self.setStyleSheet(f"background-color: {self._bg}; border: none;")
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
            event.accept()
            return
        super().mousePressEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(self._arrow_color), 2,
                   Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.RoundCap,
                   Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        cx = self.width() // 2
        cy = self.height() // 2
        # Same geometry as ArrowToggle down arrow
        painter.drawLine(cx - 5, cy - 2, cx, cy + 3)
        painter.drawLine(cx,     cy + 3, cx + 5, cy - 2)


def resource_path(relative_path):
    return os.path.join(BASE_DIR, relative_path)



def _get_hwnd(widget):
    try:
        return int(widget.winId())
    except Exception:
        return None


def _force_dark(hwnd):
    try:
        v = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(v), ctypes.sizeof(v))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(v), ctypes.sizeof(v))
    except Exception:
        pass


def set_window_title_bar_color(window):
    hwnd = _get_hwnd(window)
    if hwnd:
        _force_dark(hwnd)


def _keep_dark(window):
    try:
        if not window.isVisible():
            return
    except RuntimeError:
        return  # widget already deleted — stop the timer chain
    hwnd = _get_hwnd(window)
    if hwnd:
        _force_dark(hwnd)
    QTimer.singleShot(2000, lambda: _keep_dark(window))


def _keep_topmost(window, pause_flag=None):
    """Repeatedly re-assert Win32 HWND_TOPMOST + Qt raise so no other window
    can sneak in front.  Runs every 200 ms for the dialog's lifetime.
    Pass a one-element list [False] as pause_flag; set it to True to pause."""
    try:
        if not window.isVisible():
            return
        if pause_flag and pause_flag[0]:
            QTimer.singleShot(200, lambda: _keep_topmost(window, pause_flag))
            return
        # Qt-level raise
        window.raise_()
        window.activateWindow()
        # Win32-level re-pin every tick so other apps cannot steal z-order
        hwnd = _get_hwnd(window)
        if hwnd:
            HWND_TOPMOST = -1
            SWP_NOMOVE   = 0x0002
            SWP_NOSIZE   = 0x0001
            ctypes.windll.user32.SetWindowPos(
                hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
    except Exception:
        return
    QTimer.singleShot(200, lambda: _keep_topmost(window, pause_flag))


def _remove_minmax_buttons(window):
    """Strip minimize and maximize buttons using Win32 style flags."""
    try:
        hwnd = _get_hwnd(window)
        if not hwnd:
            return
        GWL_STYLE      = -16
        WS_MINIMIZEBOX = 0x00020000
        WS_MAXIMIZEBOX = 0x00010000
        style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
        style &= ~WS_MINIMIZEBOX
        style &= ~WS_MAXIMIZEBOX
        ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, style)
        # Force redraw of the frame
        SWP_NOMOVE     = 0x0002
        SWP_NOSIZE     = 0x0001
        SWP_NOZORDER   = 0x0004
        SWP_FRAMECHANGED = 0x0020
        ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED)
    except Exception:
        pass


def _make_dialog(parent, title):
    top = parent.window() if parent is not None else parent
    d = QDialog(top)
    d.setWindowTitle(title)
    d.setStyleSheet(f"background-color: {BG_MAIN};")
    d.setWindowModality(Qt.WindowModality.WindowModal)
    d.setSizeGripEnabled(False)
    hwnd = _get_hwnd(d)
    if hwnd:
        _force_dark(hwnd)
    def _setup():
        _remove_minmax_buttons(d)
        hwnd2 = _get_hwnd(d)
        if hwnd2:
            _force_dark(hwnd2)
    QTimer.singleShot(1, _setup)
    return d


def _topmost_worker(hwnd, stop_event):
    HWND_TOPMOST = -1
    SWP_NOMOVE   = 0x0002
    SWP_NOSIZE   = 0x0001
    while not stop_event.is_set():
        try:
            ctypes.windll.user32.SetWindowPos(
                hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
        except Exception:
            pass
        stop_event.wait(0.05)


def _show_dialog(parent, d):
    d.adjustSize()
    d.setFixedSize(d.size())
    pw = parent.width()
    ph = parent.height()
    dw = d.width()
    dh = d.height()
    parent_pos = parent.mapToGlobal(QPoint(0, 0))
    rx = parent_pos.x() + (pw // 2) - (dw // 2)
    ry = parent_pos.y() + (ph // 2) - (dh // 2)
    d.move(rx, ry)
    _keep_dark(d)
    top_level = parent.window() if parent is not None else parent
    try:
        top_level.activateWindow()
    except Exception:
        pass
    d.exec()
    try:
        top_level.activateWindow()
    except Exception:
        pass


def show_warning(parent, title, message):
    _beep()
    d = _make_dialog(parent, title)

    layout = QVBoxLayout(d)
    layout.setContentsMargins(6, 8, 6, 8)
    layout.setSpacing(0)

    # Pin width so wordwrap constrains correctly; height auto-fits via adjustSize()
    d.setFixedWidth(235)

    label = QLabel(message)
    label.setStyleSheet(f"color: white; background-color: {BG_MAIN};")
    label.setFont(QFont("Segoe UI", 10))
    label.setWordWrap(True)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(label)
    layout.addSpacing(6)

    btn = QPushButton("OK")
    btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    btn.setFixedSize(60, 22)
    btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
    btn.clicked.connect(lambda: d.accept())
    layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)

    d.adjustSize()
    _show_dialog(parent, d)


def show_mismatch_dialog(parent, title, rows, question):
    _beep()
    result = [None]
    d = _make_dialog(parent, title)

    layout = QVBoxLayout(d)
    layout.setContentsMargins(20, 16, 20, 16)

    # Header message
    header = QLabel("The loaded trainer does not match the running game.")
    header.setStyleSheet(f"color: white; background-color: {BG_MAIN};")
    header.setFont(QFont("Segoe UI", 10))
    header.setWordWrap(True)
    layout.addWidget(header)

    COL_FG   = "#9fb1cc"
    HDR_FONT = QFont("Segoe UI", 8); HDR_FONT.setBold(True)
    LBL_FONT = QFont("Segoe UI", 9)
    VAL_FONT = QFont("Segoe UI", 9); VAL_FONT.setBold(True)

    table_frame = QFrame()
    table_frame.setStyleSheet("background-color: #0a1628;")
    tbl = QGridLayout(table_frame)
    tbl.setContentsMargins(10, 8, 10, 8)
    tbl.setHorizontalSpacing(0)
    tbl.setVerticalSpacing(1)

    for col, text in enumerate(["", "Console", "Trainer"]):
        h = QLabel(text)
        h.setStyleSheet(f"color: {COL_FG}; background-color: #0a1628;")
        h.setFont(HDR_FONT)
        if col == 0:
            h.setStyleSheet(h.styleSheet() + " padding-right: 12px;")
            h.setMinimumWidth(70)
        elif col == 1:
            h.setStyleSheet(h.styleSheet() + " padding-right: 18px;")
        tbl.addWidget(h, 0, col, Qt.AlignmentFlag.AlignLeft)

    for row_i, (lbl_text, console_val, trainer_val) in enumerate(rows, start=1):
        match = console_val.strip().lower() == trainer_val.strip().lower()
        row_fg = "#00ff88" if match else "#ff4d4d"

        lbl = QLabel(lbl_text)
        lbl.setStyleSheet(f"color: {COL_FG}; background-color: #0a1628; padding-right: 12px;")
        lbl.setFont(LBL_FONT)
        tbl.addWidget(lbl, row_i, 0, Qt.AlignmentFlag.AlignLeft)

        cv = QLabel(console_val)
        cv.setStyleSheet(f"color: {row_fg}; background-color: #0a1628; padding-right: 18px;")
        cv.setFont(VAL_FONT)
        tbl.addWidget(cv, row_i, 1, Qt.AlignmentFlag.AlignLeft)

        tv = QLabel(trainer_val)
        tv.setStyleSheet(f"color: {row_fg}; background-color: #0a1628;")
        tv.setFont(VAL_FONT)
        tbl.addWidget(tv, row_i, 2, Qt.AlignmentFlag.AlignLeft)

    layout.addWidget(table_frame)

    # Footer / question
    footer = QLabel(question)
    footer.setStyleSheet(f"color: #9fb1cc; background-color: {BG_MAIN};")
    footer.setFont(QFont("Segoe UI", 9))
    footer.setWordWrap(True)
    layout.addWidget(footer)

    # Buttons
    def choose(yes):
        result[0] = yes
        d.accept()

    btn_layout = QHBoxLayout()
    btn_layout.addStretch()

    yes_btn = QPushButton("Yes")
    yes_btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    yes_btn.setStyleSheet(f"""
        QPushButton {{
            color: white;
            background-color: {ACCENT_RED};
            border: none;
            padding: 5px 18px;
        }}
        QPushButton:hover {{
            background-color: {ACCENT_GRAY};
        }}
    """)
    yes_btn.clicked.connect(lambda: choose(True))
    btn_layout.addWidget(yes_btn)

    no_btn = QPushButton("No")
    no_btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    no_btn.setStyleSheet(f"""
        QPushButton {{
            color: white;
            background-color: {ACCENT_GRAY};
            border: none;
            padding: 5px 18px;
        }}
        QPushButton:hover {{
            background-color: {BG_LIST};
        }}
    """)
    no_btn.clicked.connect(lambda: choose(False))
    btn_layout.addWidget(no_btn)

    layout.addLayout(btn_layout)

    d.setMinimumWidth(400)
    d.setMinimumHeight(300)
    _show_dialog(parent, d)
    return result[0] if result[0] is not None else False


def show_confirm_replace(parent, title, message):
    _beep()
    result = [None]
    d = _make_dialog(parent, title)

    layout = QVBoxLayout(d)
    layout.setContentsMargins(20, 16, 20, 16)

    label = QLabel(message)
    label.setStyleSheet(f"color: white; background-color: {BG_MAIN};")
    font = QFont("Segoe UI", 10)
    label.setFont(font)
    label.setWordWrap(False)
    layout.addWidget(label)

    from PySide6.QtGui import QFontMetrics
    fm = QFontMetrics(font)
    longest = max(message.split("\n"), key=lambda l: fm.horizontalAdvance(l))
    needed_width = fm.horizontalAdvance(longest) + 60  # 60px for margins
    d.setMinimumWidth(max(320, needed_width))

    def choose(yes):
        result[0] = yes
        d.accept()

    btn_layout = QHBoxLayout()
    btn_layout.addStretch()

    yes_btn = QPushButton("Yes")
    yes_btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    yes_btn.setFixedSize(60, 22)
    yes_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
    yes_btn.clicked.connect(lambda: choose(True))
    btn_layout.addWidget(yes_btn)

    btn_layout.addSpacing(8)

    no_btn = QPushButton("No")
    no_btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    no_btn.setFixedSize(60, 22)
    no_btn.setStyleSheet(_bevel_qss(ACCENT_GRAY, "white", "bold 9pt", "#555566"))
    no_btn.clicked.connect(lambda: choose(False))
    btn_layout.addWidget(no_btn)

    layout.addLayout(btn_layout)

    d.setMinimumHeight(120)
    _show_dialog(parent, d)
    return result[0] if result[0] is not None else False
