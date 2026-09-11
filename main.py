import json
import os
import platform
import re
import shutil
import urllib.request
from pathlib import Path

import discord
from discord import app_commands


TOKEN = os.getenv("DISCORD_BOT_TOKEN")
WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")


def read_text(path: str):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return None


def first_line(path: str):
    value = read_text(path)
    return value.splitlines()[0] if value else None


def parse_meminfo():
    data = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        match = re.match(r"^(\w+):\s+(\d+)\s+kB$", line)
        if match:
            data[match.group(1)] = int(match.group(2)) * 1024
    return data


def memory_report():
    m = parse_meminfo()
    limits = []
    for path in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        value = first_line(path)
        if value and value != "max":
            try:
                limits.append(int(value))
            except ValueError:
                pass
    return {
        "total": m.get("MemTotal"),
        "available": m.get("MemAvailable"),
        "swap_total": m.get("SwapTotal"),
        "swap_free": m.get("SwapFree"),
        "limit": min(limits) if limits else None,
    }


def namespaces_report():
    result = {}
    for name in (
        "cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
        "time", "time_for_children", "user", "uts",
    ):
        try:
            result[name] = os.readlink(f"/proc/self/ns/{name}")
        except OSError:
            result[name] = "unavailable"
    return result


def capabilities_report():
    status = read_text("/proc/self/status") or ""
    result = {}
    for key in (
        "Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd",
        "NoNewPrivs", "Seccomp", "Seccomp_filters",
    ):
        match = re.search(rf"^{re.escape(key)}:\s*(.+)$", status, re.MULTILINE)
        result[key] = match.group(1).strip() if match else "unavailable"
    return result


def mounts_report():
    interesting = []
    raw = read_text("/proc/self/mountinfo") or ""
    for line in raw.splitlines():
        left_right = line.split(" - ", 1)
        if len(left_right) != 2:
            continue
        left, right = left_right
        fields = left.split()
        if len(fields) < 6:
            continue
        mount_point = fields[4]
        options = fields[5]
        right_fields = right.split()
        fs_type = right_fields[0] if right_fields else "unknown"
        source = right_fields[1] if len(right_fields) > 1 else "unknown"
        if mount_point in {"/", "/proc", "/sys", "/dev", "/run"} or mount_point.startswith(("/host", "/mnt", "/media", "/var/run")):
            interesting.append((mount_point, source, fs_type, options))
    return interesting[:40]


def cgroup_report():
    paths = (
        "/sys/fs/cgroup/cgroup.controllers",
        "/sys/fs/cgroup/cgroup.subtree_control",
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/cpu.max",
        "/sys/fs/cgroup/pids.max",
    )
    return {path: (read_text(path) or "unavailable")[:500] for path in paths}


def process_report():
    try:
        pids = [x for x in os.listdir("/proc") if x.isdigit()]
        return {"self_pid": os.getpid(), "visible_pid_count": len(pids)}
    except OSError:
        return {"self_pid": os.getpid(), "visible_pid_count": None}


def network_report():
    try:
        interfaces = sorted(os.listdir("/sys/class/net"))
    except OSError:
        interfaces = []
    return {"interfaces": interfaces, "resolv_conf": read_text("/etc/resolv.conf") or "unavailable"}


def disk_report():
    total, used, free = shutil.disk_usage("/")
    return {"total": total, "used": used, "free": free}


def audit():
    return {
        "host": platform.node(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "identity": {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups()},
        "memory": memory_report(),
        "namespaces": namespaces_report(),
        "capabilities": capabilities_report(),
        "mounts": mounts_report(),
        "cgroups": cgroup_report(),
        "processes": process_report(),
        "network": network_report(),
        "disk": disk_report(),
    }


def fmt_bytes(value):
    if value is None:
        return "unknown"
    value = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return "unknown"


def render(report):
    m = report["memory"]
    c = report["capabilities"]
    i = report["identity"]
    p = report["processes"]
    lines = [
        "**Ping Host — container isolation audit**",
        f"Host: `{report['host']}`",
        f"OS: `{report['os']}`",
        f"Python: `{report['python']}`",
        f"CPU visible: `{report['cpu_count']}`",
        f"RAM visible: `{fmt_bytes(m['total'])}`",
        f"RAM available: `{fmt_bytes(m['available'])}`",
        f"cgroup RAM limit: `{fmt_bytes(m['limit'])}`",
        f"UID/GID: `{i['uid']}/{i['gid']}`",
        f"Groups: `{i['groups']}`",
        f"Visible PIDs: `{p['visible_pid_count']}`",
        f"NoNewPrivs: `{c['NoNewPrivs']}`",
        f"Seccomp: `{c['Seccomp']}` / filters `{c['Seccomp_filters']}`",
        f"Effective capabilities: `{c['CapEff']}`",
        f"Bounding capabilities: `{c['CapBnd']}`",
        "",
        "**Namespaces**",
    ]
    for name, value in report["namespaces"].items():
        lines.append(f"`{name}` = `{value}`")

    lines.append("\n**Interesting mounts**")
    for mount_point, source, fs_type, options in report["mounts"]:
        lines.append(f"`{mount_point}` ← `{source}` ({fs_type}; `{options}`)")

    lines.append("\n**cgroups**")
    for path, value in report["cgroups"].items():
        lines.append(f"`{path}` = `{value}`")

    lines.append("\n**Network**")
    lines.append(f"Interfaces: `{', '.join(report['network']['interfaces'])}`")
    lines.append("\nRead-only audit; no escape attempt, persistence, DoS, or host modification.")
    return "\n".join(lines)


def send_webhook(text: str):
    if not WEBHOOK:
        return
    payload = json.dumps({"content": text[:1900]}).encode("utf-8")
    request = urllib.request.Request(
        WEBHOOK,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10):
        pass


class SecurityBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()


client = SecurityBot()


@client.tree.command(name="audit", description="Run a read-only container isolation audit")
async def audit_command(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    text = render(audit())
    await interaction.followup.send("Auditoria concluída. Resultado enviado para o canal de testes.", ephemeral=True)
    if WEBHOOK:
        try:
            send_webhook(text)
        except Exception as exc:
            await interaction.followup.send(f"Webhook falhou: `{type(exc).__name__}`", ephemeral=True)
    else:
        for start in range(0, len(text), 1900):
            await interaction.followup.send(f"```text\n{text[start:start + 1900]}\n```", ephemeral=True)


if not TOKEN:
    raise SystemExit("Set DISCORD_BOT_TOKEN in the hosting platform.")

client.run(TOKEN)
