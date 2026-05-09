# config.py — stripped for standalone PS Payload Injector
import os, sys

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        windll.user32.SetProcessDPIAware()
    except Exception:
        pass

if getattr(sys, 'frozen', False):
    APP_DIR  = os.path.dirname(sys.executable)
    BASE_DIR = sys._MEIPASS
else:
    APP_DIR  = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = APP_DIR

GAME_DATA_DIR  = os.path.join(os.path.expanduser("~"), "Documents",
                               "PS_Payload_Injector", "data")
CONFIG_FILE    = os.path.join(GAME_DATA_DIR, "settings.json")
PAYLOADS_DIR   = os.path.join(GAME_DATA_DIR, "payloads")

PAYLOAD_PS4_FILE = "ps4debug_v1_1_19.bin"
PAYLOAD_PS5_FILE = "ps5debug_v1_0b5.elf"

os.makedirs(GAME_DATA_DIR, exist_ok=True)

# UI COLOR SCHEME
BG_MAIN          = "#000820"
BG_LIST          = "#000514"
ACCENT_RED       = "#7c0000"
ACCENT_GRAY      = "#121a2d"
LOG_BG           = "#00030a"
META_LABEL_COLOR = "#ff8c00"
ERROR_TEXT_COLOR = "#ff4d4d"
INFO_TEXT_COLOR  = "#ffa500"
FOUND_TEXT_COLOR = "#00aaff"

# Mutable globals
_ps_port = "9090"
