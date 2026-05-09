# theme.py

import os, tempfile
from config import (
    BG_MAIN, BG_LIST, ACCENT_RED, ACCENT_GRAY,
    LOG_BG, META_LABEL_COLOR,
)


GLOBAL_QSS = f"""

/* ── Scrollbars (vertical) ───────────────────────────────────────────────── */
QScrollBar:vertical {{
    background-color: {BG_LIST};
    width: 8px;
    margin: 0px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background-color: #1e2d4a;
    min-height: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: #2e3d5a;
}}
QScrollBar::handle:vertical:pressed {{
    background-color: {ACCENT_RED};
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0px;
    background: none;
    border: none;
}}
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {{
    background: none;
}}

/* ── Scrollbars (horizontal) ─────────────────────────────────────────────── */
QScrollBar:horizontal {{
    background-color: {BG_LIST};
    height: 8px;
    margin: 0px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background-color: #1e2d4a;
    min-width: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: #2e3d5a;
}}
QScrollBar::handle:horizontal:pressed {{
    background-color: {ACCENT_RED};
}}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0px;
    background: none;
    border: none;
}}
QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {{
    background: none;
}}

/* ── Menus ───────────────────────────────────────────────────────────────── */
QMenu {{
    background-color: #1e2233;
    color: #c8e0f0;
    border: 1px solid #2a3a58;
    padding: 3px 0px;
    font: 9px 'Segoe UI';
}}
QMenu::item {{
    padding: 5px 24px 5px 12px;
    background: transparent;
    margin: 0px;
}}
QMenu::item:selected {{
    background-color: {ACCENT_RED};
    color: white;
}}
QMenu::item:disabled {{
    color: #555566;
}}
QMenu::separator {{
    height: 1px;
    background-color: #2a3a58;
    margin: 3px 8px;
}}

/* ── Tooltips ────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: #0d1830;
    color: #ccd6f6;
    border: 1px solid #2a3a58;
    padding: 4px 8px;
    font: 9px 'Segoe UI';
}}

/* ── Checkboxes ──────────────────────────────────────────────────────────── */
QCheckBox {{
    color: #ccd6f6;
    spacing: 8px;
    font: 9px 'Segoe UI';
    background: transparent;
}}
QCheckBox::indicator {{
    width: 13px;
    height: 13px;
    border: 1px solid white;
    background-color: white;
    padding: 1px;
}}
QCheckBox:disabled {{
    color: #555566;
}}

/* ── Radio buttons ───────────────────────────────────────────────────────── */
QRadioButton {{
    color: #ccd6f6;
    spacing: 8px;
    font: 9px 'Segoe UI';
    background: transparent;
}}
QRadioButton::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid #3a4a6a;
    background-color: #0a1628;
    border-radius: 7px;
}}
QRadioButton::indicator:checked {{
    background-color: {BG_LIST};
    border-color: white;
    border-width: 3px;
}}
QRadioButton::indicator:unchecked:hover {{
    border-color: {META_LABEL_COLOR};
}}
QRadioButton:disabled {{
    color: #555566;
}}

/* ── Message boxes ───────────────────────────────────────────────────────── */
QMessageBox {{
    background-color: {BG_MAIN};
}}
QMessageBox QLabel {{
    color: white;
    font: 9px 'Segoe UI';
    background: transparent;
    min-width: 280px;
}}
QMessageBox QPushButton {{
    background-color: {ACCENT_GRAY};
    color: white;
    border: none;
    padding: 5px 18px;
    font: bold 9px 'Segoe UI';
    min-width: 64px;
}}
QMessageBox QPushButton:hover {{
    background-color: #1e2d4a;
}}
QMessageBox QPushButton:default {{
    background-color: {ACCENT_RED};
}}
QMessageBox QPushButton:default:hover {{
    background-color: #a01010;
}}

/* ── Dialogs ─────────────────────────────────────────────────────────────── */
QDialog {{
    background-color: {BG_MAIN};
}}

/* ── Scroll areas ────────────────────────────────────────────────────────── */
QScrollArea {{
    background-color: {BG_LIST};
    border: none;
}}
QAbstractScrollArea > QWidget {{
    background-color: {BG_LIST};
}}

/* ── Line edits ──────────────────────────────────────────────────────────── */
QLineEdit {{
    background-color: #0a1628;
    color: white;
    border: 1px solid #1e2d4a;
    border-radius: 0px;
    padding: 2px 6px;
    font: 9px 'Segoe UI';
    selection-background-color: #1e6fcc;
    selection-color: white;
}}
QLineEdit:focus {{
    border-color: {META_LABEL_COLOR};
}}
QLineEdit:read-only {{
    color: #6a8aaa;
    border-color: #0e1a2e;
}}
QLineEdit:disabled {{
    color: #3a4a60;
    background-color: #06101e;
    border-color: #0e1a2e;
}}

/* ── Text edits ──────────────────────────────────────────────────────────── */
QTextEdit {{
    background-color: {LOG_BG};
    color: #00ff41;
    border: none;
    font: 8px 'Consolas';
    selection-background-color: #1e6fcc;
    selection-color: white;
}}
QTextEdit:focus {{
    border: none;
    outline: none;
}}
"""


def apply_theme(app):
    from PySide6.QtGui import QPalette, QColor
    from PySide6.QtCore import Qt

    app.setStyle("Fusion")

    pal = app.palette()
    pal.setColor(QPalette.ColorRole.Window,           QColor(BG_MAIN))
    pal.setColor(QPalette.ColorRole.WindowText,       QColor("#ccd6f6"))
    pal.setColor(QPalette.ColorRole.Base,             QColor(BG_LIST))
    pal.setColor(QPalette.ColorRole.AlternateBase,    QColor("#0a1628"))
    pal.setColor(QPalette.ColorRole.ToolTipBase,      QColor("#0d1830"))
    pal.setColor(QPalette.ColorRole.ToolTipText,      QColor("#ccd6f6"))
    pal.setColor(QPalette.ColorRole.Text,             QColor("#ccd6f6"))
    pal.setColor(QPalette.ColorRole.BrightText,       Qt.GlobalColor.white)
    pal.setColor(QPalette.ColorRole.Button,           QColor(ACCENT_GRAY))
    pal.setColor(QPalette.ColorRole.ButtonText,       Qt.GlobalColor.white)
    pal.setColor(QPalette.ColorRole.Highlight,        QColor("#1e6fcc"))
    pal.setColor(QPalette.ColorRole.HighlightedText,  Qt.GlobalColor.white)
    pal.setColor(QPalette.ColorRole.Link,             QColor("#00aaff"))
    pal.setColor(QPalette.ColorRole.LinkVisited,      QColor("#7c4dff"))
    pal.setColor(QPalette.ColorRole.Mid,              QColor("#1e2d4a"))
    pal.setColor(QPalette.ColorRole.Dark,             QColor("#000514"))
    pal.setColor(QPalette.ColorRole.Shadow,           QColor("#000000"))
    pal.setColor(QPalette.ColorRole.Midlight,         QColor("#0a1628"))

    pal.setColor(QPalette.ColorGroup.Disabled,
                 QPalette.ColorRole.Text,       QColor("#555566"))
    pal.setColor(QPalette.ColorGroup.Disabled,
                 QPalette.ColorRole.ButtonText, QColor("#555566"))
    pal.setColor(QPalette.ColorGroup.Disabled,
                 QPalette.ColorRole.WindowText, QColor("#555566"))
    pal.setColor(QPalette.ColorGroup.Disabled,
                 QPalette.ColorRole.Base,       QColor("#06101e"))
    app.setPalette(pal)

    app.setStyleSheet(GLOBAL_QSS)
