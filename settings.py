import os, json
from config import CONFIG_FILE, GAME_DATA_DIR


def load_settings():
    defaults = {
        "api": "New API", "save_new_api_json": False, "save_old_api_json": False,
        "clear_log_on_load": False, "ps_ip": "", "ps_ip_history": [],
        "ps_port": "9090", "ps_port_history": [], "always_on_top": False,
        "toolbar_layout": None, "save_as_absolute": False,
        "filter_by_live_title": False, "goldhen_repo": False,
    }
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            defaults.update(data)
            if "ps_ip_history" not in data and data.get("ps_ip", ""):
                defaults["ps_ip_history"] = [data["ps_ip"]]
    except Exception:
        pass
    return defaults


def save_settings(api, save_new, save_old, clear_log=False, ps_ip="", ps_ip_history=None,
                  ps_port="9090", ps_port_history=None, always_on_top=False,
                  toolbar_layout=None, save_as_absolute=False, toolbar_layout_version=None,
                  filter_by_live_title=False, goldhen_repo=False):
    try:
        os.makedirs(GAME_DATA_DIR, exist_ok=True)
        existing = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                pass
        history = list(ps_ip_history) if ps_ip_history is not None else []
        if ps_ip and ps_ip not in history:
            history.insert(0, ps_ip)
        elif ps_ip and ps_ip in history:
            history.remove(ps_ip)
            history.insert(0, ps_ip)
        history = history[:10]
        port_history = list(ps_port_history) if ps_port_history is not None else []
        if ps_port and ps_port not in port_history:
            port_history.insert(0, ps_port)
        elif ps_port and ps_port in port_history:
            port_history.remove(ps_port)
            port_history.insert(0, ps_port)
        port_history = port_history[:10]
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            existing.update({
                "api":               api,
                "save_new_api_json": save_new,
                "save_old_api_json": save_old,
                "clear_log_on_load": clear_log,
                "ps_ip":             ps_ip,
                "ps_ip_history":     history,
                "ps_port":           ps_port,
                "ps_port_history":   port_history,
                "always_on_top":     always_on_top,
                "toolbar_layout":    toolbar_layout,
                "toolbar_layout_version": toolbar_layout_version,
                "save_as_absolute":  save_as_absolute,
                "filter_by_live_title": filter_by_live_title,
                "goldhen_repo":      goldhen_repo,
            })
            json.dump(existing, f, indent=4)
    except Exception:
        pass


def load_payload_paths():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("payload_paths", {})
    except Exception:
        pass
    return {}


def save_payload_paths(paths: dict):
    try:
        os.makedirs(GAME_DATA_DIR, exist_ok=True)
        data = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        data["payload_paths"] = paths
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception:
        pass
