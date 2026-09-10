import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

import requests

CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "config.json"))


def load_config():
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return None


def meminfo():
    data = {}
    raw = read_text("/proc/meminfo")
    if raw:
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    data[parts[0].rstrip(":")] = int(parts[1]) * 1024
                except ValueError:
                    pass
    return data


def memory_report():
    m = meminfo()
    total = m.get("MemTotal")
    available = m.get("MemAvailable")
    return {
        "total_ram": total,
        "available_ram": available,
        "used_ram": (total - available) if total is not None and available is not None else None,
        "swap_total": m.get("SwapTotal"),
        "swap_free": m.get("SwapFree"),
    }


def cgroup_memory():
    candidates = [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    for path in candidates:
        value = read_text(path)
        if value and value != "max":
            try:
                return int(value)
            except ValueError:
                pass
    return None


def disk_report():
    total, used, free = shutil.disk_usage("/")
    return {"total": total, "used": used, "free": free}


def basic_environment():
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "container_memory_limit": cgroup_memory(),
        "root_disk": disk_report(),
        "memory": memory_report(),
    }


def format_bytes(value):
    if value is None:
        return "unknown"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.2f} {unit}"
        n /= 1024


def build_message(report):
    mem = report["memory"]
    disk = report["root_disk"]
    return ("**Ping Host — basic security/environment check**\n"
            f"Host: `{report['hostname']}`\n"
            f"OS: `{report['os']}`\n"
            f"CPU count visible: `{report['cpu_count']}`\n"
            f"RAM visible to process: `{format_bytes(mem['total_ram'])}`\n"
            f"RAM available: `{format_bytes(mem['available_ram'])}`\n"
            f"RAM used: `{format_bytes(mem['used_ram'])}`\n"
            f"Container memory limit: `{format_bytes(report['container_memory_limit'])}`\n"
            f"Root filesystem: `{format_bytes(disk['used'])}` used / `{format_bytes(disk['total'])}` total\n")


def send_webhook(message, webhook):
    response = requests.post(webhook, json={"content": message}, timeout=10)
    response.raise_for_status()


if __name__ == "__main__":
    config = load_config()
    webhook = os.getenv("DISCORD_WEBHOOK_URL") or config.get("discord_webhook_url")
    if not webhook:
        raise SystemExit("Define discord_webhook_url in config.json or DISCORD_WEBHOOK_URL")
    send_webhook(build_message(basic_environment()), webhook)
