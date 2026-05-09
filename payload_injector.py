import os
import sys
import json
import shutil
import ctypes
import threading
import time
from typing import Optional

os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.window=false")
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
os.environ.setdefault("QT_SCALE_FACTOR_ROUNDING_POLICY", "PassThrough")

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFrame, QTextEdit,
    QFileDialog, QGridLayout, QSizePolicy, QDialog,
)
from PySide6.QtCore import Qt, Signal, Slot, QTimer, QPoint, QRect, QEvent
from PySide6.QtGui import QFont, QFontMetrics, QIcon, QCursor

import config as _cfg
from config import (
    BG_MAIN, BG_LIST, ACCENT_RED, ACCENT_GRAY, LOG_BG,
    META_LABEL_COLOR, ERROR_TEXT_COLOR, INFO_TEXT_COLOR, FOUND_TEXT_COLOR,
    PAYLOADS_DIR, PAYLOAD_PS4_FILE, PAYLOAD_PS5_FILE,
)
from settings import load_settings, save_settings, load_payload_paths, save_payload_paths
from theme import apply_theme
from ui_utils import ChevronButton, _bevel_qss, resource_path, _force_dark, _remove_minmax_buttons
from injection import InjectionEngine, InjectionResult, InjectionStatus


def _firewall_rule_ok(port: int) -> bool:
    import subprocess, tempfile
    ps1 = tempfile.NamedTemporaryFile(delete=False, suffix=".ps1",
                                      mode="w", encoding="utf-8")
    ps1.write(f"""
$port = '{port}'
$hasBlock = $false
$hasAllow = $false
Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {{
    $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if ($pf -and ($pf.LocalPort -eq $port -or $pf.LocalPort -eq 'Any')) {{
        if ($_.Action -eq 'Block') {{ $hasBlock = $true }}
        if ($_.Action -eq 'Allow') {{ $hasAllow = $true }}
    }}
}}
if ($hasBlock) {{ exit 1 }}
if (-not $hasAllow) {{ exit 2 }}
exit 0
""")
    ps1.close()
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1.name],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(ps1.name)
        except Exception:
            pass


def _apply_firewall_rules_elevated() -> bool:
    import tempfile
    ps1 = tempfile.NamedTemporaryFile(delete=False, suffix=".ps1",
                                      mode="w", encoding="utf-8")
    ps1.write(
        "Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue | ForEach-Object {\n"
        "    $p = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue\n"
        "    if ($p -and ($p.LocalPort -eq '755' -or $p.LocalPort -eq '744')) {\n"
        "        Remove-NetFirewallRule -InputObject $_\n"
        "    }\n"
        "}\n"
    )
    ps1.close()

    bat = tempfile.NamedTemporaryFile(delete=False, suffix=".bat",
                                      mode="w", encoding="utf-8")
    bat.write("\r\n".join([
        f'powershell -NoProfile -ExecutionPolicy Bypass -File "{ps1.name}"',
        'netsh advfirewall firewall delete rule name="Python PS4DBG"       >nul 2>&1',
        'netsh advfirewall firewall delete rule name="TEST_BLOCK_PS4DBG"   >nul 2>&1',
        'netsh advfirewall firewall delete rule name="PS4DBG Python Debug"  >nul 2>&1',
        'netsh advfirewall firewall delete rule name="PS4DBG Python Main"   >nul 2>&1',
        'netsh advfirewall firewall add rule name="Python PS4DBG" dir=in action=allow protocol=TCP localport=755 profile=any',
        'netsh advfirewall firewall add rule name="Python PS4DBG" dir=in action=allow protocol=TCP localport=744 profile=any',
        'netsh advfirewall firewall add rule name="Python PS4DBG" dir=out action=allow protocol=TCP localport=755 profile=any',
        'netsh advfirewall firewall add rule name="Python PS4DBG" dir=out action=allow protocol=TCP localport=744 profile=any',
    ]))
    bat.close()

    class _SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p), ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p), ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong), ("hIconOrMonitor", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    sei = _SHELLEXECUTEINFO()
    sei.cbSize     = ctypes.sizeof(sei)
    sei.fMask      = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb     = "runas"
    sei.lpFile     = "cmd.exe"
    sei.lpParameters = f'/c "{bat.name}"'
    sei.nShow      = 0
    ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    if not ok or not sei.hProcess:
        return False
    ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 15000)
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    time.sleep(0.5)
    return True


def _styled_btn(text, bg, fg="white", hover_bg=None, height=24, bold=True):
    btn = QPushButton(text)
    btn.setFixedHeight(height)
    btn.setStyleSheet(_bevel_qss(bg, fg, "bold 9pt" if bold else "9pt", hover_bg))
    return btn


def _confirm_dialog(parent, title: str, message: str) -> bool:
    d = QDialog(parent)
    d.setWindowTitle(title)
    d.setWindowFlags(Qt.Dialog | Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
    d.setStyleSheet(f"background-color: {BG_MAIN};")

    layout = QVBoxLayout(d)
    layout.setContentsMargins(20, 16, 20, 16)
    layout.setSpacing(12)

    font = QFont("Segoe UI", 10)
    lbl = QLabel(message)
    lbl.setFont(font)
    lbl.setStyleSheet("color: white; background: transparent;")
    lbl.setWordWrap(False)
    layout.addWidget(lbl)

    fm = QFontMetrics(font)
    longest = max(message.split("\n"), key=lambda l: fm.horizontalAdvance(l))
    d.setMinimumWidth(max(320, fm.horizontalAdvance(longest) + 60))

    result = [False]

    btn_row = QHBoxLayout()
    btn_row.addStretch(1)

    yes_btn = QPushButton("Yes")
    yes_btn.setFixedSize(60, 22)
    yes_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
    yes_btn.clicked.connect(lambda: (result.__setitem__(0, True), d.accept()))

    no_btn = QPushButton("No")
    no_btn.setFixedSize(60, 22)
    no_btn.setStyleSheet(_bevel_qss(ACCENT_GRAY, "white", "bold 9pt", "#555566"))
    no_btn.clicked.connect(d.reject)

    btn_row.addWidget(yes_btn)
    btn_row.addSpacing(8)
    btn_row.addWidget(no_btn)
    layout.addLayout(btn_row)

    def _setup():
        _force_dark(int(d.winId()))
        _remove_minmax_buttons(d)
    QTimer.singleShot(1, _setup)
    d.exec()
    return result[0]


class _DropdownPopup(QFrame):
    item_selected     = Signal(str)
    item_deleted      = Signal(str)
    closed_externally = Signal()

    def __init__(self, parent, items, current, allow_delete=True,
                 width=180, row_h=24, no_delete_items=None):
        super().__init__(
            None,
            Qt.Tool | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint |
            Qt.WindowDoesNotAcceptFocus | Qt.WindowStaysOnTopHint,
        )
        self.setFixedWidth(width)
        self._row_h           = row_h
        self._allow_delete    = allow_delete
        self._no_delete_items = no_delete_items or set()
        self._opener          = None
        self._externally_closed = False
        self._build(items, current)

    def _build(self, items, current):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setStyleSheet(f"background-color: {ACCENT_GRAY};")
        for item in items:
            row = QWidget()
            row.setFixedHeight(self._row_h)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(0)
            is_cur = (item == current)
            bg = "#1a3a5c" if is_cur else ACCENT_GRAY
            row.setStyleSheet(f"background-color: {bg};")

            lbl = QLabel(item)
            lbl.setStyleSheet(
                f"color: white; font: {'bold' if is_cur else 'normal'} 9pt 'Segoe UI'; "
                "padding-left: 10px; background: transparent;"
            )
            lbl.setCursor(QCursor(Qt.PointingHandCursor))
            rl.addWidget(lbl, 1)

            def _make_click(v):
                def _f(e): self.item_selected.emit(v)
                return _f
            lbl.mousePressEvent = _make_click(item)

            def _hover_enter(e, r=row):
                r.setStyleSheet("background-color: #1e2d4a;")
            def _hover_leave(e, r=row, b=bg):
                r.setStyleSheet(f"background-color: {b};")
            row.enterEvent = _hover_enter
            row.leaveEvent = _hover_leave

            if self._allow_delete and item not in self._no_delete_items:
                del_lbl = QLabel("x")
                del_lbl.setFixedWidth(20)
                del_lbl.setAlignment(Qt.AlignCenter)
                del_lbl.setStyleSheet(
                    "color: #666e7a; font: bold 11pt 'Segoe UI'; background: transparent;"
                )
                del_lbl.setCursor(QCursor(Qt.PointingHandCursor))

                def _dh_enter(e, d=del_lbl):
                    d.setStyleSheet("color: #ff4444; font: bold 11pt 'Segoe UI'; background: transparent;")
                def _dh_leave(e, d=del_lbl):
                    d.setStyleSheet("color: #666e7a; font: bold 11pt 'Segoe UI'; background: transparent;")
                def _make_del(v):
                    def _f(e): self.item_deleted.emit(v)
                    return _f

                del_lbl.enterEvent = _dh_enter
                del_lbl.leaveEvent = _dh_leave
                del_lbl.mousePressEvent = _make_del(item)
                rl.addWidget(del_lbl)

            layout.addWidget(row)
        self.adjustSize()

    def popup_below(self, widget: QWidget, opener: QWidget = None):
        self._opener = opener
        gp = widget.mapToGlobal(QPoint(0, widget.height()))
        self.move(gp)
        self.show()
        self.raise_()
        QTimer.singleShot(0, lambda: QApplication.instance().installEventFilter(self))

    def _opener_contains(self, gpos: QPoint) -> bool:
        if not self._opener:
            return False
        tl = self._opener.mapToGlobal(QPoint(0, 0))
        return QRect(tl, self._opener.size()).contains(gpos)

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.MouseButtonPress, QEvent.NonClientAreaMouseButtonPress):
            gpos = event.globalPosition().toPoint()
            if not self.geometry().contains(gpos) and not self._opener_contains(gpos):
                self._externally_closed = True
                self.hide()
                self._externally_closed = False
        elif event.type() == QEvent.ApplicationDeactivate:
            self._externally_closed = True
            self.hide()
            self._externally_closed = False
        return False

    def hideEvent(self, event):
        QApplication.instance().removeEventFilter(self)
        if getattr(self, "_externally_closed", False):
            self.closed_externally.emit()
        super().hideEvent(event)

    def focusOutEvent(self, event):
        self.hide()
        super().focusOutEvent(event)


class PayloadInjectorWindow(QMainWindow):
    _inject_done            = Signal(object)
    log_signal              = Signal(str)
    _probe_signal           = Signal(bool)
    _firewall_prompt_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PS Payload Injector v1.0 By hejran7")
        self.setStyleSheet(f"background-color: {BG_MAIN};")
        self.setMinimumSize(440, 320)

        _ico = resource_path("icon.ico")
        if os.path.exists(_ico):
            self.setWindowIcon(QIcon(_ico))

        _s = load_settings()
        self._saved_ps_ip     = _s.get("ps_ip", "")
        self._ps_ip_history   = _s.get("ps_ip_history", [])
        self._ps_port_history = _s.get("ps_port_history", [])
        _cfg._ps_port         = _s.get("ps_port", "9090")
        self._payload_paths   = load_payload_paths()
        self._payload_injected = False
        self.injection_engine  = InjectionEngine()
        self._dd_popup: Optional[_DropdownPopup] = None

        self._build_ui()
        self._inject_done.connect(self._on_inject_result)
        self.log_signal.connect(self._append_log)
        self._probe_signal.connect(self._on_probe_result)
        self._firewall_prompt_signal.connect(self._on_firewall_prompt)

        os.makedirs(PAYLOADS_DIR, exist_ok=True)
        _src = os.path.join(_cfg.BASE_DIR, "data", "payloads")
        if os.path.isdir(_src):
            for fn in os.listdir(_src):
                src = os.path.join(_src, fn)
                dst = os.path.join(PAYLOADS_DIR, fn)
                if os.path.isfile(src) and not os.path.exists(dst):
                    try:
                        shutil.copy2(src, dst)
                    except Exception:
                        pass

        QTimer.singleShot(0, self._apply_win32_frame)
        QTimer.singleShot(300, self._check_firewall)
        QTimer.singleShot(100, self._probe_ps4debug)

    def _apply_win32_frame(self):
        try:
            _force_dark(int(self.winId()))
        except Exception:
            pass

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        ROW_H  = 22
        LBL_H  = 16
        FLD_BG = "#0a1628"
        ARW_FG = "#999999"

        def _lbl(text):
            w = QLabel(text)
            w.setFixedHeight(LBL_H)
            w.setStyleSheet("color: #9fb1cc; font: 8pt 'Segoe UI';")
            return w

        grid = QWidget()
        gl = QGridLayout(grid)
        gl.setContentsMargins(0, 0, 0, 0)
        gl.setHorizontalSpacing(8)
        gl.setVerticalSpacing(6)
        gl.setColumnStretch(0, 1)
        gl.setColumnStretch(1, 0)
        gl.setColumnStretch(2, 0)
        gl.setColumnMinimumWidth(1, 90)
        gl.setColumnMinimumWidth(2, 90)

        ip_col   = QWidget()
        ip_col_l = QVBoxLayout(ip_col)
        ip_col_l.setContentsMargins(0, 0, 0, 0)
        ip_col_l.setSpacing(2)
        ip_col_l.addWidget(_lbl("PlayStation IP"))

        ip_frame = QFrame()
        ip_frame.setFixedHeight(ROW_H)
        ip_frame.setStyleSheet(f"background-color: {FLD_BG}; border: 1px solid #3a4a6a;")
        ip_fl = QHBoxLayout(ip_frame)
        ip_fl.setContentsMargins(0, 0, 0, 0)
        ip_fl.setSpacing(0)

        self._ip_edit = QLineEdit(self._saved_ps_ip or "")
        self._ip_edit.setPlaceholderText("e.g. 192.168.1.100")
        self._ip_edit.setStyleSheet(
            f"background-color: {FLD_BG}; color: white; border: none; "
            "font: 9pt 'Segoe UI'; padding-left: 6px;"
        )
        ip_fl.addWidget(self._ip_edit, 1)

        sep_ip = QFrame()
        sep_ip.setFixedWidth(1)
        sep_ip.setStyleSheet("background-color: #3a4a6a;")
        ip_fl.addWidget(sep_ip)

        self._ip_arrow = ChevronButton(bg="#1e2d4a", hover_bg="#2a3d5a", arrow_color=ARW_FG)
        self._ip_arrow.setFixedSize(20, ROW_H - 2)
        self._ip_arrow.clicked.connect(self._open_ip_dd)
        ip_fl.addWidget(self._ip_arrow)

        ip_col_l.addWidget(ip_frame)
        self._ip_frame = ip_frame
        gl.addWidget(ip_col, 0, 0, Qt.AlignTop)

        port_col   = QWidget()
        port_col.setFixedWidth(90)
        port_col_l = QVBoxLayout(port_col)
        port_col_l.setContentsMargins(0, 0, 0, 0)
        port_col_l.setSpacing(2)
        port_col_l.addWidget(_lbl("Port"))

        port_frame = QFrame()
        port_frame.setFixedHeight(ROW_H)
        port_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        port_frame.setStyleSheet(f"background-color: {FLD_BG}; border: 1px solid #3a4a6a;")
        port_fl = QHBoxLayout(port_frame)
        port_fl.setContentsMargins(0, 0, 0, 0)
        port_fl.setSpacing(0)

        self._port_edit = QLineEdit(str(_cfg._ps_port or "9090"))
        self._port_edit.setStyleSheet(
            f"background-color: {FLD_BG}; color: white; border: none; "
            "font: 9pt 'Segoe UI'; padding-left: 6px;"
        )
        port_fl.addWidget(self._port_edit, 1)

        sep_port = QFrame()
        sep_port.setFixedWidth(1)
        sep_port.setStyleSheet("background-color: #3a4a6a;")
        port_fl.addWidget(sep_port)

        self._port_arrow = ChevronButton(bg="#1e2d4a", hover_bg="#2a3d5a", arrow_color=ARW_FG)
        self._port_arrow.setFixedSize(20, ROW_H - 2)
        self._port_arrow.clicked.connect(self._open_port_dd)
        port_fl.addWidget(self._port_arrow)

        port_col_l.addWidget(port_frame)
        self._port_frame = port_frame
        gl.addWidget(port_col, 0, 1, Qt.AlignTop)

        inj_col   = QWidget()
        inj_col.setFixedWidth(90)
        inj_col_l = QVBoxLayout(inj_col)
        inj_col_l.setContentsMargins(0, 0, 0, 0)
        inj_col_l.setSpacing(2)
        inj_col_l.addWidget(_lbl(" "))

        self._inj_btn = _styled_btn("Inject", ACCENT_RED, "white", "#a01010", ROW_H)
        self._inj_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._inj_btn.clicked.connect(self._do_inject)
        inj_col_l.addWidget(self._inj_btn)
        gl.addWidget(inj_col, 0, 2, Qt.AlignTop)

        mode_col   = QWidget()
        mode_col_l = QVBoxLayout(mode_col)
        mode_col_l.setContentsMargins(0, 0, 0, 0)
        mode_col_l.setSpacing(2)
        mode_col_l.addWidget(_lbl("Mode"))

        _saved_mode = self._payload_paths.get("injector_mode", "PS4Debug")
        if _saved_mode not in ("PS4Debug", "PS5Debug"):
            _saved_mode = "PS4Debug"
        self._mode_val = _saved_mode

        mode_frame = QFrame()
        mode_frame.setFixedHeight(ROW_H)
        mode_frame.setStyleSheet(f"background-color: {ACCENT_RED}; border: 1px solid #999999;")
        mode_frame.setCursor(QCursor(Qt.PointingHandCursor))
        mfl = QHBoxLayout(mode_frame)
        mfl.setContentsMargins(8, 0, 0, 0)
        mfl.setSpacing(0)
        self._mode_lbl = QLabel(_saved_mode)
        self._mode_lbl.setStyleSheet(
            "color: white; font: bold 9pt 'Segoe UI'; background: transparent; border: none;"
        )
        mfl.addWidget(self._mode_lbl, 1)
        sep_mode = QFrame()
        sep_mode.setFixedWidth(1)
        sep_mode.setStyleSheet("background-color: #cc2222;")
        mfl.addWidget(sep_mode)
        _mode_chev = ChevronButton(bg=ACCENT_RED, hover_bg="#a01010", arrow_color="white")
        _mode_chev.setFixedSize(20, ROW_H - 2)
        _mode_chev.clicked.connect(self._open_mode_dd)
        mfl.addWidget(_mode_chev)
        mode_frame.mousePressEvent = lambda e: self._open_mode_dd()
        self._mode_btn = mode_frame
        mode_col_l.addWidget(self._mode_btn)
        gl.addWidget(mode_col, 1, 0, Qt.AlignTop)

        fw_wrap   = QWidget()
        fw_wrap_l = QVBoxLayout(fw_wrap)
        fw_wrap_l.setContentsMargins(0, 0, 0, 0)
        fw_wrap_l.setSpacing(2)
        fw_wrap_l.addWidget(_lbl(" "))
        self._fix_port_btn = _styled_btn(
            "Fix Port 755 (Firewall)", "#1a3a5c", "white", "#1e4a7a", ROW_H, bold=False
        )
        self._fix_port_btn.clicked.connect(self._fix_port_755)
        fw_wrap_l.addWidget(self._fix_port_btn)
        gl.addWidget(fw_wrap, 1, 1, 1, 2, Qt.AlignTop)

        root.addWidget(grid)

        self._path_box   = QWidget()
        pb_l = QVBoxLayout(self._path_box)
        pb_l.setContentsMargins(0, 0, 0, 0)
        pb_l.setSpacing(2)

        self._path_label = QLabel("Payload Path  (Built-in)")
        self._path_label.setStyleSheet("color: #9fb1cc; font: 8pt 'Segoe UI';")
        pb_l.addWidget(self._path_label)

        path_row   = QWidget()
        path_row_l = QHBoxLayout(path_row)
        path_row_l.setContentsMargins(0, 0, 0, 0)
        path_row_l.setSpacing(4)

        path_wrap = QFrame()
        path_wrap.setFixedHeight(ROW_H)
        path_wrap.setStyleSheet("background-color: #0a1628; border: 1px solid #3a4a6a;")
        path_wrap.setAcceptDrops(True)
        path_wrap.dragEnterEvent = self._on_drag_enter
        path_wrap.dropEvent      = self._on_drop
        pw_l = QHBoxLayout(path_wrap)
        pw_l.setContentsMargins(4, 0, 4, 0)
        self._path_edit = QLineEdit()
        self._path_edit.setStyleSheet(
            "background-color: #0a1628; color: white; border: none; font: 9pt 'Segoe UI';"
        )
        self._path_edit.setAcceptDrops(False)
        pw_l.addWidget(self._path_edit)
        path_row_l.addWidget(path_wrap, 1)
        self._path_wrap = path_wrap

        self._browse_btn = _styled_btn("...", "#0a1628", "#9fb1cc", "#1e2d4a", ROW_H, bold=True)
        self._browse_btn.setFixedWidth(30)
        self._browse_btn.clicked.connect(self._browse_path)
        path_row_l.addWidget(self._browse_btn)

        self._builtin_btn = _styled_btn("Use Custom", "#1a3a5c", "white", "#1e4a7a", ROW_H, bold=False)
        self._builtin_btn.setFixedWidth(90)
        self._builtin_btn.clicked.connect(self._toggle_builtin)
        path_row_l.addWidget(self._builtin_btn)

        pb_l.addWidget(path_row)
        root.addWidget(self._path_box)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("font: 8pt 'Segoe UI';")
        self._status_lbl.hide()
        root.addWidget(self._status_lbl)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1e2d4a;")
        root.addWidget(sep)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMinimumHeight(90)
        self._log.setStyleSheet(
            f"background-color: {LOG_BG}; color: #00ff41; border: none; font: 8pt 'Consolas';"
        )
        root.addWidget(self._log, 1)

        self._MODE_DEFAULTS = {
            "PS4Debug": os.path.join(PAYLOADS_DIR, PAYLOAD_PS4_FILE),
            "PS5Debug": os.path.join(PAYLOADS_DIR, PAYLOAD_PS5_FILE),
        }
        self._use_builtin = True
        self._update_path_row()

        self._ip_edit.editingFinished.connect(self._on_ip_edited)
        self._port_edit.editingFinished.connect(self._save_port_from_entry)

    def _close_dd(self):
        if self._dd_popup:
            self._dd_popup.hide()
            self._dd_popup = None

    def _on_dd_closed_externally(self):
        self._dd_popup = None

    def _open_ip_dd(self):
        if self._dd_popup:
            self._close_dd()
            return
        if not self._ps_ip_history:
            return
        cur = self._ip_edit.text().strip()
        popup = _DropdownPopup(self, self._ps_ip_history, cur, allow_delete=True,
                               width=self._ip_frame.width(), row_h=22)
        popup.item_selected.connect(
            lambda v: (self._ip_edit.setText(v), self._close_dd(), self._save_ip_from_entry())
        )
        popup.item_deleted.connect(self._delete_ip)
        popup.closed_externally.connect(self._on_dd_closed_externally)
        popup.popup_below(self._ip_frame, opener=self._ip_arrow)
        self._dd_popup = popup

    def _delete_ip(self, v):
        if v in self._ps_ip_history:
            self._ps_ip_history.remove(v)
        if self._ip_edit.text().strip() == v:
            self._ip_edit.setText("")
        if self._saved_ps_ip == v:
            self._saved_ps_ip = ""
        self._save_ip_from_entry()
        self._close_dd()
        if self._ps_ip_history:
            self._open_ip_dd()

    def _open_port_dd(self):
        if self._dd_popup:
            self._close_dd()
            return
        _PORT_DEFAULTS = ["9090", "9021", "9020"]
        seen, port_list = set(), []
        for p in self._ps_port_history + _PORT_DEFAULTS:
            if p not in seen:
                seen.add(p)
                port_list.append(p)
        cur = self._port_edit.text().strip()
        popup = _DropdownPopup(self, port_list, cur, allow_delete=True,
                               width=self._port_frame.width(), row_h=22,
                               no_delete_items=set(_PORT_DEFAULTS))
        popup.item_selected.connect(
            lambda v: (self._port_edit.setText(v), self._close_dd(), self._save_port_from_entry())
        )
        popup.item_deleted.connect(self._delete_port)
        popup.closed_externally.connect(self._on_dd_closed_externally)
        popup.popup_below(self._port_frame, opener=self._port_arrow)
        self._dd_popup = popup

    def _delete_port(self, v):
        _PORT_DEFAULTS = ["9090", "9021", "9020"]
        if v in self._ps_port_history:
            self._ps_port_history.remove(v)
        if self._port_edit.text().strip() == v:
            self._port_edit.setText(_PORT_DEFAULTS[0])
        self._close_dd()
        self._open_port_dd()

    def _open_mode_dd(self):
        if self._dd_popup:
            self._close_dd()
            return
        popup = _DropdownPopup(self, ["PS4Debug", "PS5Debug"], self._mode_val,
                               allow_delete=False, width=self._mode_btn.width(), row_h=22)
        popup.item_selected.connect(self._pick_mode)
        popup.closed_externally.connect(self._on_dd_closed_externally)
        popup.popup_below(self._mode_btn, opener=self._mode_btn)
        self._dd_popup = popup

    def _pick_mode(self, val):
        self._mode_val = val
        self._mode_lbl.setText(val)
        self._close_dd()
        self._payload_paths["injector_mode"] = val
        save_payload_paths(self._payload_paths)
        self._use_builtin = True
        self._update_path_row()
        default_port = "9090" if val == "PS4Debug" else "9021"
        self._port_edit.setText(default_port)
        _cfg._ps_port = default_port
        self._persist_settings()
        self._payload_injected = False
        self._inj_btn.setEnabled(True)
        self._inj_btn.setText("Inject")
        self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
        self._status_lbl.hide()
        QTimer.singleShot(0, self._probe_ps4debug)

    def _update_path_row(self):
        mode    = self._mode_val
        builtin = self._norm(self._MODE_DEFAULTS.get(mode, ""))
        saved   = self._norm(self._payload_paths.get(mode, ""))

        if self._use_builtin:
            self._path_edit.setText(builtin)
            self._path_edit.setReadOnly(True)
            self._path_edit.setStyleSheet(
                "background-color: #0a1628; color: #6a8aaa; border: none; font: 9pt 'Segoe UI';"
            )
            self._browse_btn.setEnabled(False)
            self._builtin_btn.setText("Use Custom")
            self._builtin_btn.setStyleSheet(_bevel_qss("#1a3a5c", "white", "9pt", "#1e4a7a"))
            self._path_label.setText("Payload Path  (Built-in)")
        else:
            self._path_edit.setText(saved if saved else builtin)
            self._path_edit.setReadOnly(False)
            self._path_edit.setStyleSheet(
                "background-color: #0a1628; color: white; border: none; font: 9pt 'Segoe UI';"
            )
            self._browse_btn.setEnabled(True)
            self._builtin_btn.setText("Use Built-in")
            self._builtin_btn.setStyleSheet(_bevel_qss("#1a5c2a", "white", "9pt", "#2a8c3a"))
            self._path_label.setText("Payload Path  (Custom)")

    def _toggle_builtin(self):
        mode = self._mode_val
        if self._use_builtin:
            self._use_builtin = False
            self._path_edit.setReadOnly(False)
            self._path_edit.setStyleSheet(
                "background-color: #0a1628; color: white; border: none; font: 9pt 'Segoe UI';"
            )
            self._browse_btn.setEnabled(True)
            self._builtin_btn.setText("Use Built-in")
            self._builtin_btn.setStyleSheet(_bevel_qss("#1a5c2a", "white", "9pt", "#2a8c3a"))
            self._path_label.setText("Payload Path  (Custom)")
        else:
            self._use_builtin = True
            builtin = self._norm(self._MODE_DEFAULTS.get(mode, ""))
            self._path_edit.setText(builtin)
            self._path_edit.setReadOnly(True)
            self._path_edit.setStyleSheet(
                "background-color: #0a1628; color: #6a8aaa; border: none; font: 9pt 'Segoe UI';"
            )
            self._browse_btn.setEnabled(False)
            self._builtin_btn.setText("Use Custom")
            self._builtin_btn.setStyleSheet(_bevel_qss("#1a3a5c", "white", "9pt", "#1e4a7a"))
            self._path_label.setText("Payload Path  (Built-in)")

    def _on_drag_enter(self, event):
        from PySide6.QtCore import QUrl
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].toLocalFile().lower().endswith((".bin", ".elf", ".payload")):
                event.acceptProposedAction()
                self._path_wrap.setStyleSheet(
                    "background-color: #0a1628; border: 1px solid #00aaff;"
                )
                return
        event.ignore()

    def _on_drop(self, event):
        from PySide6.QtCore import QUrl
        self._path_wrap.setStyleSheet(
            "background-color: #0a1628; border: 1px solid #3a4a6a;"
        )
        urls = event.mimeData().urls()
        if not urls:
            return
        fp = urls[0].toLocalFile()
        if not fp.lower().endswith((".bin", ".elf", ".payload")):
            return
        mode = self._mode_val
        self._use_builtin = False
        self._path_edit.setText(self._norm(fp))
        self._path_edit.setReadOnly(False)
        self._path_edit.setStyleSheet(
            "background-color: #0a1628; color: white; border: none; font: 9pt 'Segoe UI';"
        )
        self._browse_btn.setEnabled(True)
        self._builtin_btn.setText("Use Built-in")
        self._builtin_btn.setStyleSheet(_bevel_qss("#1a5c2a", "white", "9pt", "#2a8c3a"))
        self._path_label.setText("Payload Path  (Custom)")
        self._save_path_for_mode()
        if self._payload_injected:
            self._payload_injected = False
            self._inj_btn.setEnabled(True)
            self._inj_btn.setText("Inject")
            self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
            self._status_lbl.hide()
        event.acceptProposedAction()

    def _browse_path(self):
        cur = self._path_edit.text().strip()
        start_dir = (
            os.path.dirname(cur)
            if cur and os.path.exists(os.path.dirname(cur))
            else PAYLOADS_DIR
        )
        fp, _ = QFileDialog.getOpenFileName(
            self, "Select Payload", start_dir,
            "Payload files (*.bin *.elf *.payload);;All files (*.*)",
        )
        if fp:
            self._path_edit.setText(self._norm(fp))
            self._save_path_for_mode()

    def _save_path_for_mode(self):
        mode    = self._mode_val
        fp      = self._path_edit.text().strip()
        builtin = self._norm(self._MODE_DEFAULTS.get(mode, ""))
        if fp and not self._use_builtin and fp != builtin:
            self._payload_paths[mode] = fp
            save_payload_paths(self._payload_paths)

    @staticmethod
    def _norm(p: str) -> str:
        return p.replace("\\", "/")

    def _save_ip_from_entry(self):
        ip = self._ip_edit.text().strip()
        if not ip:
            self._saved_ps_ip = ""
            return
        self._saved_ps_ip = ip
        if ip in self._ps_ip_history:
            self._ps_ip_history.remove(ip)
        self._ps_ip_history.insert(0, ip)
        self._ps_ip_history = self._ps_ip_history[:10]
        self._persist_settings()

    def _on_ip_edited(self):
        self._save_ip_from_entry()
        if self._payload_injected:
            self._payload_injected = False
            self._inj_btn.setEnabled(True)
            self._inj_btn.setText("Inject")
            self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
            self._status_lbl.hide()
        self._probe_ps4debug()

    def _save_port_from_entry(self):
        port_s = self._port_edit.text().strip()
        if not port_s:
            return
        if port_s in self._ps_port_history:
            self._ps_port_history.remove(port_s)
        self._ps_port_history.insert(0, port_s)
        self._ps_port_history = self._ps_port_history[:10]
        _cfg._ps_port = port_s
        self._persist_settings()

    def _persist_settings(self):
        save_settings(
            "New API", False, False,
            ps_ip=self._saved_ps_ip,
            ps_ip_history=self._ps_ip_history,
            ps_port=_cfg._ps_port,
            ps_port_history=self._ps_port_history,
        )

    def log(self, msg: str):
        self.log_signal.emit(msg)

    @Slot(str)
    def _append_log(self, msg: str):
        self._log.append(msg)
        sb = self._log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _show_status(self, msg: str, color: str):
        self._status_lbl.setText(msg)
        self._status_lbl.setStyleSheet(f"color: {color}; font: 8pt 'Segoe UI';")
        self._status_lbl.show()

    def _probe_ps4debug(self):
        ip = self._saved_ps_ip
        if not ip:
            return
        self.log(f"[PROBE] Checking {ip}:744 ...")

        def _run():
            import socket
            running = False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                s.connect((ip, 744))
                s.close()
                running = True
            except Exception:
                running = False
            self._probe_signal.emit(running)

        threading.Thread(target=_run, daemon=True).start()

    @Slot(bool)
    def _on_probe_result(self, running: bool):
        tool = "ps4debug" if self._mode_val == "PS4Debug" else "ps5debug"
        if running:
            self._payload_injected = True
            self._inj_btn.setEnabled(False)
            self._inj_btn.setText("Injected")
            self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_GRAY, "#555566", "bold 9pt"))
            self._show_status(f"{tool} already running - payload was previously injected.", FOUND_TEXT_COLOR)
        else:
            self.log(f"[PROBE] Port 744 not responding on {self._saved_ps_ip} - ready to inject.")

    def _check_firewall(self):
        import platform
        if platform.system() != "Windows":
            return
        appdata   = os.environ.get("APPDATA", os.path.dirname(os.path.abspath(__file__)))
        fw_flag   = os.path.join(appdata, "PS_Payload_Injector", "firewall.json")
        os.makedirs(os.path.dirname(fw_flag), exist_ok=True)
        try:
            if os.path.exists(fw_flag):
                with open(fw_flag, "r", encoding="utf-8") as f:
                    if json.load(f).get("firewall_fixed"):
                        return
        except Exception:
            pass

        def _chk():
            if _firewall_rule_ok(744) and _firewall_rule_ok(755):
                try:
                    with open(fw_flag, "w", encoding="utf-8") as f:
                        json.dump({"firewall_fixed": True}, f)
                except Exception:
                    pass
                return

            self._firewall_prompt_signal.emit(fw_flag)

        threading.Thread(target=_chk, daemon=True).start()

    @Slot(str)
    def _on_firewall_prompt(self, fw_flag: str):
        if _confirm_dialog(
            self, "Firewall Setup",
            "PS Payload Injector needs inbound TCP ports 744 and 755 open on all\n"
            "network profiles to reach the PS4/PS5.\n\n"
            "Apply firewall rules automatically?\n"
            "(A UAC prompt will appear - click Yes to allow it.)",
        ):
            def _do():
                ok = _apply_firewall_rules_elevated()
                if ok:
                    try:
                        with open(fw_flag, "w", encoding="utf-8") as f2:
                            json.dump({"firewall_fixed": True}, f2)
                    except Exception:
                        pass
                    self.log_signal.emit(
                        "[OK] Firewall rules applied - ports 744 and 755 are now open."
                    )
                else:
                    self.log_signal.emit(
                        "[FAIL] Firewall fix cancelled or failed (UAC denied)."
                    )
            threading.Thread(target=_do, daemon=True).start()

    def _fix_port_755(self):
        import platform
        if platform.system() != "Windows":
            self.log("[Firewall] Firewall management is only available on Windows.")
            return
        if not _confirm_dialog(
            self, "Fix Ports 744 & 755 (Firewall)",
            "Apply firewall rules for TCP ports 744 and 755 on all network profiles?\n\n"
            "A UAC prompt will appear - click Yes to allow it.",
        ):
            return
        self.log("[Firewall] Applying rules for ports 744 and 755 ...")

        def _do():
            ok = _apply_firewall_rules_elevated()
            self.log_signal.emit(
                "[OK] Firewall rules applied - ports 744 and 755 are now open."
                if ok else
                "[FAIL] Firewall fix cancelled or failed (UAC denied)."
            )

        threading.Thread(target=_do, daemon=True).start()

    def _do_inject(self):
        ip       = self._ip_edit.text().strip()
        port_str = self._port_edit.text().strip()
        mode     = self._mode_val

        if not ip:
            self._show_status("Enter a PS4/PS5 IP address.", ERROR_TEXT_COLOR)
            return
        try:
            port = int(port_str)
        except ValueError:
            self._show_status("Invalid port number.", ERROR_TEXT_COLOR)
            return

        fpath = self._path_edit.text().strip()
        if not fpath or not os.path.isfile(fpath):
            self._show_status("Payload file not found.", ERROR_TEXT_COLOR)
            return

        if ip in self._ps_ip_history:
            self._ps_ip_history.remove(ip)
        self._ps_ip_history.insert(0, ip)
        self._ps_ip_history = self._ps_ip_history[:10]
        self._saved_ps_ip = ip

        port_s = str(port)
        if port_s in self._ps_port_history:
            self._ps_port_history.remove(port_s)
        self._ps_port_history.insert(0, port_s)
        self._ps_port_history = self._ps_port_history[:10]
        _cfg._ps_port = port_s
        self._persist_settings()

        self._show_status("Injecting...", INFO_TEXT_COLOR)
        self._inj_btn.setEnabled(False)

        self.injection_engine.configure(ip=ip, payload_port=port)
        self.injection_engine.send_payload(fpath, lambda r: self._inject_done.emit(r), mode)

    @Slot(object)
    def _on_inject_result(self, result: InjectionResult):
        if result.status == InjectionStatus.OK:
            self._show_status("Payload sent successfully", FOUND_TEXT_COLOR)
            self._payload_injected = True
            self._inj_btn.setEnabled(False)
            self._inj_btn.setText("Injected")
            self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_GRAY, "#555566", "bold 9pt"))
        else:
            color = INFO_TEXT_COLOR if result.status == InjectionStatus.TIMEOUT else ERROR_TEXT_COLOR
            self._show_status("Payload send failed", color)
            self._inj_btn.setEnabled(True)
            self._inj_btn.setText("Inject")
            self._inj_btn.setStyleSheet(_bevel_qss(ACCENT_RED, "white", "bold 9pt", "#a01010"))
        self.log(f"[INJECT] {result.mode} -> {result.ip}:{result.port} - {result.message}")

    def moveEvent(self, event):
        self._close_dd()
        super().moveEvent(event)

    def closeEvent(self, event):
        mode = self._mode_val
        if not self._use_builtin:
            fp      = self._path_edit.text().strip()
            builtin = self._norm(self._MODE_DEFAULTS.get(mode, ""))
            if fp and fp != builtin:
                self._payload_paths[mode] = fp
        save_payload_paths(self._payload_paths)
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 9))
    apply_theme(app)

    window = PayloadInjectorWindow()
    window.resize(460, 260)
    window.setWindowOpacity(0.0)

    try:
        hwnd = int(window.winId())
        v    = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(v), ctypes.sizeof(v))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(v), ctypes.sizeof(v))
    except Exception:
        pass

    window.show()

    def _center_and_reveal():
        ag = QApplication.primaryScreen().availableGeometry()
        fg = window.frameGeometry()
        x  = ag.x() + (ag.width()  - fg.width())  // 2
        y  = ag.y() + (ag.height() - fg.height()) // 2
        window.move(x, y)
        window.setWindowOpacity(1.0)

    QTimer.singleShot(50, _center_and_reveal)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
