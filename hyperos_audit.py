#!/usr/bin/env python3
"""Read-only HyperOS privacy audit for Windows + Android Platform Tools.

The collector deliberately uses only informational ADB commands.  It never
installs, removes, disables, freezes, grants, revokes, or clears anything on
the phone.  Results are written locally as Markdown/CSV plus raw evidence.

The parser is intentionally tolerant of Android/HyperOS releases: several
commands have changed output format over time, and unavailable diagnostics are
reported as unavailable instead of being treated as proof of absence.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence


PROJECT_NAME = "HyperOS Security Audit"
PLATFORM_TOOLS_URL = "https://developer.android.com/tools/releases/platform-tools"
DEFAULT_TIMEOUT = 45

# These are the complete command strings issued by this program.  Keeping the
# list visible makes the read-only boundary reviewable and testable.
READ_ONLY_SHELL_COMMANDS = {
    "getprop",
    "pm list packages -f -U --user 0",
    "pm list packages -f -U",
    "dumpsys package",
    "dumpsys appops",
    "dumpsys usagestats",
    "dumpsys activity services",
    "dumpsys jobscheduler",
    "dumpsys media_projection",
    "dumpsys netstats --proto",
    "dumpsys netstats",
    "dumpsys connectivity",
    "cat /proc/net/xt_qtaguid/stats",
    "cat /proc/net/tcp",
    "cat /proc/net/tcp6",
    "ss -tunap",
}
FORBIDDEN_TOKENS = {
    " install ",
    " uninstall ",
    " disable ",
    " enable ",
    " freeze ",
    " unfreeze ",
    " grant ",
    " revoke ",
    " clear ",
    " reset ",
    " set-",
    " settings put",
    " rm ",
    " reboot",
}

SENSITIVE_PERMISSIONS = {
    "android.permission.PACKAGE_USAGE_STATS": ("usage statistics", "high"),
    "android.permission.QUERY_ALL_PACKAGES": ("broad package visibility", "medium"),
    "android.permission.READ_PHONE_STATE": ("telephony/device identifiers", "high"),
    "android.permission.READ_PHONE_NUMBERS": ("phone number", "high"),
    "android.permission.READ_PRIVILEGED_PHONE_STATE": ("privileged telephony/device identifiers", "critical"),
    "android.permission.ACCESS_FINE_LOCATION": ("precise location", "high"),
    "android.permission.ACCESS_COARSE_LOCATION": ("coarse location", "medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("background location", "high"),
    "android.permission.READ_CALL_LOG": ("call history", "high"),
    "android.permission.WRITE_CALL_LOG": ("call history modification", "high"),
    "android.permission.READ_CONTACTS": ("contacts", "high"),
    "android.permission.WRITE_CONTACTS": ("contacts modification", "high"),
    "android.permission.READ_SMS": ("SMS messages", "high"),
    "android.permission.RECEIVE_SMS": ("incoming SMS", "high"),
    "android.permission.SEND_SMS": ("SMS sending", "high"),
    "android.permission.CAPTURE_VIDEO_OUTPUT": ("screen capture (privileged)", "critical"),
    "android.permission.PROJECT_MEDIA": ("MediaProjection/screen capture", "high"),
    "android.permission.RECORD_AUDIO": ("microphone", "high"),
    "android.permission.CAMERA": ("camera", "high"),
    "android.permission.READ_MEDIA_AUDIO": ("audio files", "medium"),
    "android.permission.READ_MEDIA_IMAGES": ("images", "medium"),
    "android.permission.READ_MEDIA_VIDEO": ("videos", "medium"),
    "android.permission.READ_EXTERNAL_STORAGE": ("shared storage", "medium"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("draw over other apps", "high"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("accessibility observation/control", "critical"),
    "android.permission.BODY_SENSORS": ("body sensors", "high"),
    "android.permission.ACTIVITY_RECOGNITION": ("physical activity", "medium"),
    "android.permission.READ_CALENDAR": ("calendar", "medium"),
}

FOCUS_TOKENS = (
    "systemhelper",
    "misight",
    "xsof",
    "com.miui.dmregservice",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def csv_safe(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(x) for x in value)
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def clean_line(value: str, limit: int = 400) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def focus_match(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in FOCUS_TOKENS)


def max_risk(risks: Iterable[str]) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": -1}
    found = list(risks)
    return max(found, key=lambda x: order.get(x, -1), default="none")


@dataclass
class CommandResult:
    command: str
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class DeviceInfo:
    serial: str = ""
    state: str = "not_connected"
    model: str = ""
    manufacturer: str = ""
    market_name: str = ""
    android_version: str = ""
    hyperos_version: str = ""
    build_id: str = ""
    incremental: str = ""
    security_patch: str = ""
    sdk: str = ""
    target_match: str = "unverified"


@dataclass
class PackageRecord:
    package: str
    path: str = ""
    uid: str = ""
    installer: str = ""
    version_name: str = ""
    version_code: str = ""
    user_id: str = ""
    shared_user_id: str = ""
    code_path: str = ""
    flags: str = ""
    signature: str = ""
    system: bool = False
    privileged: bool = False
    requested_permissions: list[str] = field(default_factory=list)
    granted_permissions: list[str] = field(default_factory=list)
    appops: list[dict[str, str]] = field(default_factory=list)
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    network_observed: bool = False
    service_evidence: list[str] = field(default_factory=list)
    job_evidence: list[str] = field(default_factory=list)
    usage_evidence: list[str] = field(default_factory=list)


@dataclass
class AuditData:
    started_at: str
    finished_at: str = ""
    adb_path: str = ""
    adb_version: str = ""
    device: DeviceInfo = field(default_factory=DeviceInfo)
    packages: list[PackageRecord] = field(default_factory=list)
    network_rows: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    raw_status: dict[str, str] = field(default_factory=dict)
    command_errors: list[dict[str, str]] = field(default_factory=list)
    evidence_files: list[str] = field(default_factory=list)
    no_device_reason: str = ""


def find_adb(explicit: str | None = None) -> Path | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    which = shutil.which("adb")
    if which:
        candidates.append(which)
    # Common Windows locations, including the path used by Android Studio.
    candidates.extend(
        [
            str(Path.cwd() / "platform-tools" / "adb.exe"),
            r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe",
            r"%ANDROID_HOME%\platform-tools\adb.exe",
            r"%ANDROID_SDK_ROOT%\platform-tools\adb.exe",
            r"C:\Android\platform-tools\adb.exe",
        ]
    )
    seen: set[str] = set()
    for candidate in candidates:
        expanded = os.path.expandvars(os.path.expanduser(candidate))
        if expanded.lower() in seen:
            continue
        seen.add(expanded.lower())
        path = Path(expanded)
        if path.is_file() and path.name.lower() in {"adb", "adb.exe"}:
            return path.resolve()
    return None


class AdbClient:
    def __init__(self, adb_path: Path, serial: str | None, timeout: int, evidence_dir: Path):
        self.adb_path = adb_path
        self.serial = serial
        self.timeout = timeout
        self.evidence_dir = evidence_dir
        self.results: list[CommandResult] = []

    def _base(self) -> list[str]:
        command = [str(self.adb_path)]
        if self.serial:
            command += ["-s", self.serial]
        return command

    def run(self, args: Sequence[str], *, name: str, timeout: int | None = None) -> CommandResult:
        start = dt.datetime.now().timestamp()
        try:
            proc = subprocess.run(
                self._base() + list(args),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
                shell=False,
            )
            result = CommandResult(
                " ".join(["adb", *list(args)]),
                proc.returncode,
                proc.stdout,
                proc.stderr,
                duration_ms=int((dt.datetime.now().timestamp() - start) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                " ".join(["adb", *list(args)]),
                None,
                exc.stdout or "",
                exc.stderr or "",
                "timeout",
                duration_ms=int((dt.datetime.now().timestamp() - start) * 1000),
            )
        except OSError as exc:
            result = CommandResult(
                " ".join(["adb", *list(args)]),
                None,
                "",
                "",
                f"{type(exc).__name__}: {exc}",
                duration_ms=int((dt.datetime.now().timestamp() - start) * 1000),
            )
        self.results.append(result)
        if name:
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
            evidence_path = self.evidence_dir / f"{safe_name}.txt"
            evidence_path.write_text(
                f"COMMAND: {result.command}\nRETURN CODE: {result.returncode}\nERROR: {result.error}\n\n"
                f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n",
                encoding="utf-8",
            )
        return result

    def shell(self, command: str, *, name: str, timeout: int | None = None) -> CommandResult:
        if command not in READ_ONLY_SHELL_COMMANDS:
            raise ValueError(f"unreviewed shell command: {command}")
        lowered = f" {command.lower()} "
        if any(token in lowered for token in FORBIDDEN_TOKENS):
            raise ValueError(f"mutating shell command is forbidden: {command}")
        return self.run(["shell", command], name=name, timeout=timeout)


def parse_devices(output: str) -> list[tuple[str, str, str]]:
    devices: list[tuple[str, str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices attached") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] in {"device", "unauthorized", "offline", "unknown", "no permissions"}:
            serial, state = parts[0], parts[1]
            details = " ".join(parts[2:])
            devices.append((serial, state, details))
    return devices


def parse_getprop(output: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in output.splitlines():
        match = re.match(r"\[([^\]]+)\]: \[([^\]]*)\]", line.strip())
        if match:
            props[match.group(1)] = match.group(2)
    return props


def choose_prop(props: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = props.get(key, "").strip()
        if value:
            return value
    return ""


def parse_package_list(output: str) -> dict[str, PackageRecord]:
    packages: dict[str, PackageRecord] = {}
    pattern = re.compile(
        r"^package:(?P<path>\S+?)=(?P<pkg>[^\s]+)(?:\s+uid:(?P<uid>\d+))?(?:\s+installer=(?P<installer>\S+))?"
    )
    for line in output.splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        data = match.groupdict()
        package = data["pkg"]
        record = packages.get(package) or PackageRecord(package=package)
        record.path = data.get("path") or record.path
        record.uid = data.get("uid") or record.uid
        record.installer = data.get("installer") or record.installer
        packages[package] = record
    return packages


def split_package_blocks(output: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    # The heading has been stable for Android's dumpsys package output, while
    # indentation and trailing punctuation differ between releases.
    heading = re.compile(r"^\s*Package \[([^\]]+)\]")
    for line in output.splitlines():
        match = heading.match(line)
        if match:
            current = match.group(1)
            blocks.setdefault(current, []).append(line)
        elif current is not None:
            blocks[current].append(line)
    return {key: "\n".join(value) for key, value in blocks.items()}


def parse_permissions_from_block(block: str) -> tuple[list[str], list[str]]:
    requested: list[str] = []
    granted: list[str] = []
    # Restrict requested parsing to permission-looking strings. This avoids
    # treating arbitrary text in dumpsys output as a permission.
    for permission in sorted(set(re.findall(r"android\.permission\.[A-Z0-9_]+", block))):
        requested.append(permission)
    for match in re.finditer(
        r"(android\.permission\.[A-Z0-9_]+)[^\n]{0,180}?granted\s*=\s*true", block, re.IGNORECASE
    ):
        granted.append(match.group(1))
    return requested, sorted(set(granted))


def parse_package_details(output: str, packages: dict[str, PackageRecord]) -> None:
    for package, block in split_package_blocks(output).items():
        record = packages.get(package) or PackageRecord(package=package)
        record.user_id = choose_regex(block, r"\buserId=(\d+)", r"\buid=(\d+)") or record.user_id
        record.uid = record.uid or record.user_id
        record.shared_user_id = choose_regex(block, r"\bsharedUserId=([^\s,]+)") or record.shared_user_id
        record.version_name = choose_regex(block, r"\bversionName=([^\s]+)") or record.version_name
        record.version_code = choose_regex(block, r"\bversionCode=([^\s]+)") or record.version_code
        record.code_path = choose_regex(block, r"\bcodePath=([^\s]+)") or record.code_path
        record.path = record.path or record.code_path
        flag_match = re.search(r"\b(?:pkgFlags|flags)=\[([^\]]*)\]", block)
        if flag_match:
            record.flags = clean_line(flag_match.group(1))
        signature_match = re.search(r"(?im)^\s*(?:signatures?|signingInfo)[^\n]*\n?(?:\s+[^\n]+)?", block)
        if signature_match:
            record.signature = clean_line(signature_match.group(0), 300)
        requested, granted = parse_permissions_from_block(block)
        record.requested_permissions = sorted(set(record.requested_permissions + requested))
        record.granted_permissions = sorted(set(record.granted_permissions + granted))
        lower_path = (record.path or record.code_path).lower()
        lower_flags = record.flags.lower()
        record.system = record.system or any(
            lower_path.startswith(prefix)
            for prefix in ("/system", "/product", "/vendor", "/odm", "/apex")
        ) or "system" in lower_flags
        record.privileged = record.privileged or "privileged" in lower_flags
        packages[package] = record


def choose_regex(text: str, *patterns: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def parse_appops(output: str) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = {}
    current: str | None = None
    package_heading = re.compile(r"^\s*Package\s+([^\s:]+):")
    operation = re.compile(
        r"^\s*(?P<op>(?:android:)?[A-Za-z0-9_.-]+)\s*:\s*(?P<mode>allow|deny|ignore|foreground|default|errored|unknown)\b(?P<rest>.*)$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        heading = package_heading.match(line)
        if heading:
            current = heading.group(1)
            result.setdefault(current, [])
            continue
        if current is None:
            continue
        match = operation.match(line)
        if match:
            result[current].append(
                {
                    "operation": match.group("op"),
                    "mode": match.group("mode").lower(),
                    "detail": clean_line(match.group("rest")),
                }
            )
    return result


def parse_network_stats(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    header_fields: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("idx ") or stripped.startswith("idx\t"):
            header_fields = re.split(r"\s+", stripped)
            continue
        if header_fields and re.match(r"^\d+\s", stripped):
            values = re.split(r"\s+", stripped)
            if len(values) >= len(header_fields):
                item = dict(zip(header_fields, values))
                uid = item.get("uid_tag_int") or item.get("uid")
                if uid and uid.isdigit():
                    rows.append(
                        {
                            "uid": int(uid),
                            "interface": item.get("iface", ""),
                            "rx_bytes": int(item.get("rx_bytes", "0") or 0),
                            "rx_packets": int(item.get("rx_packets", "0") or 0),
                            "tx_bytes": int(item.get("tx_bytes", "0") or 0),
                            "tx_packets": int(item.get("tx_packets", "0") or 0),
                            "source": "xt_qtaguid",
                        }
                    )
                    continue
        # dumpsys netstats --proto commonly uses key=value fields.
        uid_match = re.search(r"\buid(?:=|:)(\d+)", stripped, re.IGNORECASE)
        if uid_match:
            def number(name: str) -> int:
                found = re.search(rf"\b{name}(?:=|:)(\d+)", stripped, re.IGNORECASE)
                return int(found.group(1)) if found else 0

            rows.append(
                {
                    "uid": int(uid_match.group(1)),
                    "interface": choose_regex(stripped, r"\biface=(\S+)"),
                    "rx_bytes": number("rxBytes") or number("rx_bytes"),
                    "rx_packets": number("rxPackets") or number("rx_packets"),
                    "tx_bytes": number("txBytes") or number("tx_bytes"),
                    "tx_packets": number("txPackets") or number("tx_packets"),
                    "source": "dumpsys_netstats",
                }
            )
    return rows


def decode_ipv4(hex_value: str) -> str:
    try:
        raw = bytes.fromhex(hex_value)
        return ".".join(str(x) for x in raw[::-1])
    except (ValueError, TypeError):
        return hex_value


def parse_proc_tcp(output: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        local, remote, state = fields[1], fields[2], fields[3]
        if ":" not in remote:
            continue
        remote_addr, remote_port = remote.rsplit(":", 1)
        uid = ""
        # The kernel's proc_net_tcp format places uid at field 7 after the
        # leading slot. Later fields contain timeout and inode values.
        if len(fields) > 7 and fields[7].isdigit():
            uid = fields[7]
        endpoints.append(
            {
                "local": local,
                "remote_ip": decode_ipv4(remote_addr) if len(remote_addr) == 8 else remote_addr,
                "remote_port": int(remote_port, 16) if re.fullmatch(r"[0-9A-Fa-f]+", remote_port) else remote_port,
                "state": state,
                "uid": uid,
                "source": "/proc/net/tcp",
            }
        )
    return endpoints


def decode_ipv6(hex_value: str) -> str:
    try:
        raw = bytes.fromhex(hex_value)
        if len(raw) != 16:
            return hex_value
        # proc_net_tcp6 renders each 32-bit word in host byte order.
        address = b"".join(raw[offset : offset + 4][::-1] for offset in range(0, 16, 4))
        return str(ipaddress.IPv6Address(address))
    except (ValueError, TypeError):
        return hex_value


def parse_proc_tcp6(output: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        local, remote, state = fields[1], fields[2], fields[3]
        if ":" not in remote:
            continue
        remote_addr, remote_port = remote.rsplit(":", 1)
        uid = fields[7] if fields[7].isdigit() else ""
        endpoints.append(
            {
                "local": local,
                "remote_ip": decode_ipv6(remote_addr),
                "remote_port": int(remote_port, 16) if re.fullmatch(r"[0-9A-Fa-f]+", remote_port) else remote_port,
                "state": state,
                "uid": uid,
                "source": "/proc/net/tcp6",
            }
        )
    return endpoints


def attach_evidence(raw: str, package_names: Iterable[str], limit_each: int = 5) -> dict[str, list[str]]:
    lines = raw.splitlines()
    found: dict[str, list[str]] = {name: [] for name in package_names}
    for line in lines:
        lowered = line.lower()
        for package in found:
            if package.lower() in lowered and len(found[package]) < limit_each:
                found[package].append(clean_line(line))
    return found


def build_device_info(serial: str, state: str, props: dict[str, str]) -> DeviceInfo:
    model = choose_prop(props, "ro.product.model", "ro.product.device")
    market = choose_prop(props, "ro.product.marketname", "ro.product.name")
    hyperos = choose_prop(props, "ro.miui.ui.version.name", "ro.mi.os.version.name", "ro.miui.ui.version.code")
    target_match = "matched" if any("k80" in value.lower() for value in (model, market)) else "unverified"
    return DeviceInfo(
        serial=serial,
        state=state,
        model=model,
        manufacturer=choose_prop(props, "ro.product.manufacturer", "ro.product.brand"),
        market_name=market,
        android_version=choose_prop(props, "ro.build.version.release"),
        hyperos_version=hyperos,
        build_id=choose_prop(props, "ro.build.display.id", "ro.build.id"),
        incremental=choose_prop(props, "ro.build.version.incremental"),
        security_patch=choose_prop(props, "ro.build.version.security_patch"),
        sdk=choose_prop(props, "ro.build.version.sdk"),
        target_match=target_match,
    )


def collect(adb: Path, output_dir: Path, serial: str | None, timeout: int, require_device: bool) -> AuditData:
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    data = AuditData(started_at=utc_now(), adb_path=str(adb))
    client = AdbClient(adb, serial, timeout, evidence_dir)

    version = client.run(["version"], name="adb_version")
    data.adb_version = clean_line(version.stdout or version.stderr, 1000)
    client.run(["start-server"], name="adb_start_server")
    devices = client.run(["devices", "-l"], name="adb_devices")
    parsed_devices = parse_devices(devices.stdout)
    selected: tuple[str, str, str] | None = None
    if serial:
        selected = next((item for item in parsed_devices if item[0] == serial), None)
    elif len(parsed_devices) == 1:
        selected = parsed_devices[0]
    elif parsed_devices:
        selected = next((item for item in parsed_devices if item[1] == "device"), parsed_devices[0])

    if not selected or selected[1] != "device":
        reason = "No authorized device detected."
        if selected:
            reason = f"ADB device {selected[0]} is {selected[1]}; unlock the phone and accept USB debugging authorization."
        elif parsed_devices:
            reason = "ADB reported devices, but none is authorized."
        data.no_device_reason = reason
        data.device = DeviceInfo(serial=serial or (selected[0] if selected else ""), state=selected[1] if selected else "not_connected")
        data.raw_status["adb_devices"] = devices.stdout.strip()
        data.command_errors.append({"command": "adb devices -l", "error": reason})
        data.evidence_files = sorted(str(path.relative_to(output_dir)) for path in evidence_dir.glob("*.txt"))
        if require_device:
            raise RuntimeError(reason)
        data.finished_at = utc_now()
        return data

    if not serial:
        client.serial = selected[0]
    data.device.serial, data.device.state = selected[0], selected[1]

    props_result = client.shell("getprop", name="getprop")
    props = parse_getprop(props_result.stdout)
    data.device = build_device_info(selected[0], selected[1], props)
    data.raw_status["getprop_count"] = str(len(props))

    package_list = client.shell("pm list packages -f -U --user 0", name="pm_packages_user0")
    if not package_list.ok or not package_list.stdout.strip():
        package_list = client.shell("pm list packages -f -U", name="pm_packages_fallback")
    packages = parse_package_list(package_list.stdout)

    package_dump = client.shell("dumpsys package", name="dumpsys_package", timeout=max(timeout, 90))
    parse_package_details(package_dump.stdout, packages)

    appops = client.shell("dumpsys appops", name="dumpsys_appops", timeout=max(timeout, 90))
    appops_by_package = parse_appops(appops.stdout)
    for package, operations in appops_by_package.items():
        record = packages.get(package) or PackageRecord(package=package)
        record.appops = operations
        packages[package] = record

    usage = client.shell("dumpsys usagestats", name="dumpsys_usagestats", timeout=max(timeout, 90))
    services = client.shell("dumpsys activity services", name="dumpsys_activity_services", timeout=max(timeout, 90))
    jobs = client.shell("dumpsys jobscheduler", name="dumpsys_jobscheduler", timeout=max(timeout, 90))
    projection = client.shell("dumpsys media_projection", name="dumpsys_media_projection")
    names = list(packages)
    for package, lines in attach_evidence(usage.stdout, names).items():
        if lines:
            packages[package].usage_evidence = lines
    for package, lines in attach_evidence(services.stdout + "\n" + projection.stdout, names).items():
        if lines:
            packages[package].service_evidence = lines
    for package, lines in attach_evidence(jobs.stdout, names).items():
        if lines:
            packages[package].job_evidence = lines

    stats_result = client.shell("cat /proc/net/xt_qtaguid/stats", name="proc_xt_qtaguid_stats")
    stats = parse_network_stats(stats_result.stdout)
    if not stats:
        netstats = client.shell("dumpsys netstats --proto", name="dumpsys_netstats_proto", timeout=max(timeout, 90))
        stats = parse_network_stats(netstats.stdout)
    if not stats:
        netstats = client.shell("dumpsys netstats", name="dumpsys_netstats", timeout=max(timeout, 90))
        stats = parse_network_stats(netstats.stdout)
    data.network_rows = stats
    for row in stats:
        uid = str(row.get("uid", ""))
        for package in packages.values():
            if uid and uid in {package.uid, package.user_id}:
                package.network_rx_bytes += int(row.get("rx_bytes", 0) or 0)
                package.network_tx_bytes += int(row.get("tx_bytes", 0) or 0)
                package.network_observed = True

    tcp = client.shell("cat /proc/net/tcp", name="proc_net_tcp")
    tcp6 = client.shell("cat /proc/net/tcp6", name="proc_net_tcp6")
    data.endpoints = parse_proc_tcp(tcp.stdout) + parse_proc_tcp6(tcp6.stdout)
    if not data.endpoints:
        tcp_alt = client.shell("ss -tunap", name="ss_tunap")
        data.raw_status["ss_tunap"] = clean_line(tcp_alt.stdout, 2000)
    connectivity = client.shell("dumpsys connectivity", name="dumpsys_connectivity", timeout=max(timeout, 90))
    # Keep only lines containing an IP/host-looking token in the report. The
    # complete command output remains in evidence for local review.
    data.raw_status["connectivity_lines"] = str(sum(1 for line in connectivity.stdout.splitlines() if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|https?://", line)))

    data.packages = sorted(packages.values(), key=lambda package: package.package.lower())
    data.finished_at = utc_now()
    for result in client.results:
        if not result.ok:
            data.command_errors.append({"command": result.command, "error": result.error or clean_line(result.stderr, 500) or f"return code {result.returncode}"})
    data.evidence_files = sorted(str(path.relative_to(output_dir)) for path in evidence_dir.glob("*.txt"))
    return data


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_safe(row.get(key, "")) for key in fieldnames})


def package_risk(package: PackageRecord) -> tuple[str, list[str]]:
    reasons: list[str] = []
    risks: list[str] = []
    for permission in package.requested_permissions:
        if permission in SENSITIVE_PERMISSIONS:
            explanation, level = SENSITIVE_PERMISSIONS[permission]
            reasons.append(f"requests {permission} ({explanation})")
            risks.append(level)
            if permission in package.granted_permissions:
                reasons.append(f"grant observed for {permission}")
                risks.append(level)
    active_ops = [op for op in package.appops if op.get("mode") in {"allow", "foreground"}]
    if active_ops:
        reasons.append("AppOps contains allow/foreground entries: " + ", ".join(op["operation"] for op in active_ops[:8]))
        risks.append("medium")
    if package.network_observed and (package.network_rx_bytes + package.network_tx_bytes) > 0:
        reasons.append(f"UID traffic counters observed ({package.network_rx_bytes} RX / {package.network_tx_bytes} TX bytes)")
        risks.append("medium")
    if package.service_evidence:
        reasons.append("package name appears in activity/media-projection service diagnostics")
        risks.append("medium")
    if package.job_evidence:
        reasons.append("package name appears in JobScheduler diagnostics")
        risks.append("low")
    return max_risk(risks), reasons


def render_reports(data: AuditData, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    package_rows: list[dict[str, Any]] = []
    permission_rows: list[dict[str, Any]] = []
    for package in data.packages:
        risk, reasons = package_risk(package)
        package_rows.append(
            {
                "package": package.package,
                "version_name": package.version_name,
                "version_code": package.version_code,
                "uid": package.uid or package.user_id,
                "install_path": package.path or package.code_path,
                "installer": package.installer,
                "system": package.system,
                "privileged": package.privileged,
                "shared_user_id": package.shared_user_id,
                "flags": package.flags,
                "signature": package.signature,
                "requested_sensitive": [p for p in package.requested_permissions if p in SENSITIVE_PERMISSIONS],
                "granted_sensitive": [p for p in package.granted_permissions if p in SENSITIVE_PERMISSIONS],
                "network_rx_bytes": package.network_rx_bytes,
                "network_tx_bytes": package.network_tx_bytes,
                "risk": risk,
                "risk_reasons": reasons,
            }
        )
        all_permissions = sorted(set(package.requested_permissions) | set(package.granted_permissions))
        for permission in all_permissions:
            description, base_risk = SENSITIVE_PERMISSIONS.get(permission, ("non-focus permission", "none"))
            permission_rows.append(
                {
                    "package": package.package,
                    "uid": package.uid or package.user_id,
                    "permission": permission,
                    "requested": permission in package.requested_permissions,
                    "granted": permission in package.granted_permissions,
                    "description": description,
                    "risk_if_granted": base_risk,
                    "evidence": "dumpsys package",
                }
            )
    write_csv(
        output_dir / "packages.csv",
        package_rows,
        [
            "package",
            "version_name",
            "version_code",
            "uid",
            "install_path",
            "installer",
            "system",
            "privileged",
            "shared_user_id",
            "flags",
            "signature",
            "requested_sensitive",
            "granted_sensitive",
            "network_rx_bytes",
            "network_tx_bytes",
            "risk",
            "risk_reasons",
        ],
    )
    write_csv(
        output_dir / "permissions.csv",
        permission_rows,
        ["package", "uid", "permission", "requested", "granted", "description", "risk_if_granted", "evidence"],
    )

    device = data.device
    report_lines = [
        f"# {PROJECT_NAME}",
        "",
        f"审计时间（UTC）：{data.started_at} 至 {data.finished_at or '未完成'}",
        "",
        "## 结论摘要",
        "",
    ]
    if data.no_device_reason:
        report_lines += [
            f"本次运行未取得授权设备数据：**{data.no_device_reason}**",
            "因此本目录中的设备、包、权限、AppOps 和网络结论均标为未观测；没有用网上曝光的组件名单替代实测结果。连接 Redmi K80 Ultra 后重新运行即可填充报告。",
        ]
    else:
        report_lines += [
            f"已连接设备：`{device.model or '未知型号'}`（目标 Redmi K80 Ultra 匹配状态：{device.target_match}）。",
            f"发现 {len(data.packages)} 个包；网络 UID 统计行 {len(data.network_rows)} 条；可解析 TCP 端点 {len(data.endpoints)} 条。",
            "权限、服务、JobScheduler 和网络统计只代表采集时点；权限存在不等于数据已被读取，UID 流量也不等于已证明上传了某种内容。",
        ]
    report_lines += [
        "",
        "## 设备信息",
        "",
        "| 字段 | 值 |",
        "|---|---|",
        f"| ADB 路径 | `{data.adb_path}` |",
        f"| ADB 版本 | {data.adb_version or '未观测'} |",
        f"| ADB 状态 | {device.state} |",
        f"| 型号 | {device.model or '未观测'} |",
        f"| 制造商/品牌 | {device.manufacturer or '未观测'} |",
        f"| 市场名称 | {device.market_name or '未观测'} |",
        f"| Android | {device.android_version or '未观测'}（SDK {device.sdk or '未观测'}） |",
        f"| HyperOS | {device.hyperos_version or '未观测'} |",
        f"| 构建号 | {device.build_id or '未观测'} |",
        f"| 增量版本 | {device.incremental or '未观测'} |",
        f"| 安全补丁 | {device.security_patch or '未观测'} |",
        "",
        "## 方法和证据边界",
        "",
        "- 第一阶段只调用 `adb devices`, `getprop`, `pm list packages`, `dumpsys` 和 `/proc` 只读接口；脚本没有卸载、禁用、冻结、授权、撤销、清理或修改系统配置的代码路径。",
        "- 系统签名、共享 UID、特权标志和组件名称来自设备返回的 `dumpsys package`；组件不存在时报告为未发现。",
        "- 网络部分只记录 UID 计数和设备当时可见的连接端点。没有抓包、TLS 解密或内容审计，所以不能据此证明上传了什么内容。",
        "- AppOps/UsageStats 受 ROM 版本、权限和保留周期影响；命令不可用时保留错误并标记证据缺失，不把缺失当成否定证据。",
        "",
        "## 输出文件",
        "",
        "- [packages.csv](packages.csv)：包名、版本、UID、路径、系统/特权标志和 UID 流量。",
        "- [permissions.csv](permissions.csv)：请求/授予的权限及重点权限说明。",
        "- [suspicious_components.md](suspicious_components.md)：按实际发现的重点组件和证据评估。",
        "- [network_report.md](network_report.md)：UID 流量、端点和网络证据边界。",
        "- [recommendations.md](recommendations.md)：可限制与不建议修改的条件化建议。",
        "- `evidence/`：本地原始命令输出，便于复核；不要上传到第三方。",
    ]
    if data.command_errors:
        report_lines += ["", "## 采集错误或缺失", ""]
        report_lines += [f"- `{item['command']}`：{item['error']}" for item in data.command_errors]
    (output_dir / "audit_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    focus_records = [package for package in data.packages if focus_match(package.package) or any(focus_match(line) for line in package.service_evidence + package.job_evidence)]
    sensitive_records = [package for package in data.packages if any(permission in SENSITIVE_PERMISSIONS for permission in package.requested_permissions)]
    records: list[PackageRecord] = []
    seen: set[str] = set()
    for package in focus_records + sensitive_records:
        if package.package not in seen:
            records.append(package)
            seen.add(package.package)
    suspicious = [
        "# 可疑/重点组件审计",
        "",
        "组件筛选基于设备实际包名、权限、服务、任务和 AppOps 输出。`SystemHelper`、`MiSight`、`XSOF`、`com.miui.dmregservice` 仅在设备输出中出现时列入；没有出现不代表网上说法被证实或证伪。",
        "",
    ]
    if not records:
        suspicious += ["本次没有可评估的设备包记录。", ""]
    for package in records:
        risk, reasons = package_risk(package)
        suspicious += [
            f"## `{package.package}`",
            "",
            f"- **发现依据**：包列表/`dumpsys package`{'; 设备输出含重点名称' if focus_match(package.package) else ''}",
            f"- **用途线索**：系统包={package.system}，特权={package.privileged}，路径 `{package.path or package.code_path or '未观测'}`；仅凭名称不能确认用途。",
            f"- **数据读取能力**：请求重点权限 `{', '.join(p for p in package.requested_permissions if p in SENSITIVE_PERMISSIONS) or '未观测'}`；实际授予 `{', '.join(p for p in package.granted_permissions if p in SENSITIVE_PERMISSIONS) or '未观测'}`。",
            f"- **后台/访问证据**：AppOps `{clean_line(json.dumps(package.appops, ensure_ascii=False), 500) if package.appops else '未观测'}`；服务 `{'; '.join(package.service_evidence) if package.service_evidence else '未观测'}`；任务 `{'; '.join(package.job_evidence) if package.job_evidence else '未观测'}`。",
            f"- **网络上传证据**：UID 计数 RX={package.network_rx_bytes}、TX={package.network_tx_bytes} 字节（{ '观察到计数' if package.network_observed else '未观察到该 UID 计数' }）。这不能证明上传内容或目的。",
            f"- **风险等级**：**{risk}**。依据：{'; '.join(reasons) if reasons else '没有足够证据分级'}。",
            "- **不确定性**：单次采集、ROM 权限策略和 AppOps 保留周期会影响结果；需要重复采样或可选抓包模块才能判断连接频率和内容。",
            "",
        ]
    (output_dir / "suspicious_components.md").write_text("\n".join(suspicious), encoding="utf-8")

    network = [
        "# 网络行为审计",
        "",
        "网络报告只描述设备返回的计数和端点。UID 流量增加是实际网络活动证据，但不能单独证明数据内容、上传方向的业务含义或特定域名归属。",
        "",
        f"- 统计行：{len(data.network_rows)}",
        f"- 可解析 TCP 端点：{len(data.endpoints)}",
        f"- connectivity 输出中含 IP/URL 的行数：{data.raw_status.get('connectivity_lines', '未采集')}",
        "",
        "## UID 流量",
        "",
        "| UID | 包名 | RX bytes | TX bytes | 接口 | 来源 |",
        "|---:|---|---:|---:|---|---|",
    ]
    package_by_uid: dict[str, list[str]] = {}
    for package in data.packages:
        for uid in {package.uid, package.user_id}:
            if uid:
                package_by_uid.setdefault(uid, []).append(package.package)
    for row in data.network_rows:
        packages_for_uid = ", ".join(package_by_uid.get(str(row.get("uid")), [])) or "未解析包名"
        network.append(f"| {row.get('uid', '')} | {packages_for_uid} | {row.get('rx_bytes', 0)} | {row.get('tx_bytes', 0)} | {row.get('interface', '')} | {row.get('source', '')} |")
    if not data.network_rows:
        network.append("| — | 未观测 | — | — | — | 命令不可用或设备未连接 |")
    network += ["", "## 端点", "", "| UID（暂定） | 远端 IP | 端口 | 状态 | 来源 |", "|---|---|---:|---|---|"]
    for endpoint in data.endpoints:
        network.append(f"| {endpoint.get('uid') or '未解析'} | {endpoint.get('remote_ip', '')} | {endpoint.get('remote_port', '')} | {endpoint.get('state', '')} | {endpoint.get('source', '')} |")
    if not data.endpoints:
        network.append("| — | 未观测 | — | — | /proc/net/tcp 或 /proc/net/tcp6 不可用，或设备未连接 |")
    network += [
        "",
        "## 解释边界",
        "",
        "- 统计数据是采集时点或系统保留窗口的累计值，不能替代长时间序列。",
        "- `/proc/net/tcp` 和 `/proc/net/tcp6` 的 UID 映射在部分 Android 版本不完整；端点与包名的关联标为暂定。",
        "- 如需深度流量抓包，应另行设计可选模块，在用户明确授权和本地存储策略下执行；本阶段没有抓包。",
    ]
    (output_dir / "network_report.md").write_text("\n".join(network) + "\n", encoding="utf-8")

    recommendations = [
        "# 限制建议",
        "",
        "以下建议是基于证据门槛的条件化建议，不会由本工具自动执行任何修改。先在系统设置中确认依赖、备份和可恢复性。",
        "",
        "## 可以优先考虑限制",
        "",
        "1. **普通第三方应用**：若 `permissions.csv` 显示其确实被授予位置、通话记录、设备状态或屏幕捕获相关权限，且业务不需要，可在系统设置中逐项撤销，并观察功能影响。",
        "2. **已确认可选的厂商分析/反馈组件**：只有在 `suspicious_components.md` 中存在实际包名、权限和后台证据，且确认不承担电话、更新、安全或设备核心依赖时，才考虑系统设置提供的逐项限制或网络访问控制。",
        "3. **后台活动**：对存在 JobScheduler/Service 证据、又不属于核心系统依赖的应用，可先限制后台活动并重复采样，比较 UID 流量变化。",
        "",
        "## 不建议直接修改",
        "",
        "- `system_server`、电话、设置、系统 UI、权限控制、更新、安全中心、输入法和共享 UID 核心包。它们通常具有系统签名/特权或共享 UID；禁用可能导致启动、通话、通知、更新或解锁异常。",
        "- 任何仅凭名称猜测的 `SystemHelper`、`MiSight`、`XSOF` 或 `com.miui.dmregservice`。先以设备实测包信息和依赖关系为准；不存在时不要创建假设。",
        "- 不要使用卸载、`pm disable-user`、冻结、清除数据或修改系统设置的命令作为第一阶段措施。本项目严格只读。",
        "",
        "## 复核顺序",
        "",
        "1. 连接并授权目标手机后重新运行审计，确认型号、构建号和安全补丁。",
        "2. 对重点包保存本报告和 `evidence/`，在不同时间点重复两到三次，比较 AppOps、服务、任务和 UID 计数。",
        "3. 只有存在稳定的实际行为证据时，才在手机设置中做一项可逆限制，然后再次运行审计验证影响。",
        "4. 若要判断具体上传内容，单独规划本地抓包和证书/隐私边界；权限或域名本身都不能证明内容。",
    ]
    (output_dir / "recommendations.md").write_text("\n".join(recommendations) + "\n", encoding="utf-8")

    (output_dir / "audit_data.json").write_text(json.dumps(asdict(data), ensure_ascii=False, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only HyperOS privacy audit")
    parser.add_argument("--output-dir", default=".", help="local directory for reports (default: current directory)")
    parser.add_argument("--adb", help="path to official adb.exe; otherwise search PATH and common SDK locations")
    parser.add_argument("--serial", help="ADB serial when more than one device is connected")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="per-command timeout in seconds")
    parser.add_argument("--require-device", action="store_true", help="return an error instead of producing an unavailable report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    adb = find_adb(args.adb)
    if not adb:
        print("未找到 adb.exe。请安装 Android 官方 Platform Tools：", file=sys.stderr)
        print(PLATFORM_TOOLS_URL, file=sys.stderr)
        print("安装后将 platform-tools 加入 PATH，或使用 --adb <path-to-adb.exe>。", file=sys.stderr)
        return 2
    try:
        data = collect(adb, output_dir, args.serial, max(5, args.timeout), args.require_device)
    except RuntimeError as exc:
        print(f"审计未执行：{exc}", file=sys.stderr)
        return 3
    render_reports(data, output_dir)
    print(f"报告已写入：{output_dir}")
    if data.no_device_reason:
        print(f"注意：{data.no_device_reason}")
        return 4
    print(f"已审计 {len(data.packages)} 个包；证据保存在 {output_dir / 'evidence'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
