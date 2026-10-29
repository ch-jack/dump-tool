#!/usr/bin/env python3
"""Inspect the currently running FiveM client and report its server endpoint.

The probe reads process arguments, CitizenFX logs, process connections, and,
when needed, the FiveM process memory.  Verification uses the token supplied
by the caller and only keeps an endpoint that returns a valid resource list.
"""

from __future__ import print_function

import argparse
import ctypes
from ctypes import wintypes
import contextlib
import importlib.util
import ipaddress
import io
import json
import os
import re
import socket
import sys
import time
from pathlib import Path

import requests

try:
    import psutil
except ImportError:  # pragma: no cover - exercised by the CLI environment
    psutil = None


TOOL_VERSION = "0.1.0"
DEFAULT_LOG_MAX_AGE = 6 * 60 * 60
DEFAULT_LOG_FILES = 8
DEFAULT_LOG_TAIL_BYTES = 1024 * 1024
WEB_PORTS = {53, 80, 443, 8080, 8443}
GAME_PORT_HINTS = {30120, 30121, 30122, 30123, 30124, 30125}
MEMORY_CHUNK_SIZE = 1024 * 1024
MEMORY_OVERLAP_SIZE = 128
MEMORY_SCAN_MAX_REGIONS = 4096

PROCESS_CONNECT_PATTERNS = (
    re.compile(r"(?i)fivem://connect/([^\"'\s]+)"),
    re.compile(r"(?i)(?:^|\s)(?:\+connect|--connect)\s+([^\"'\s]+)"),
)
LOG_CONNECT_PATTERNS = (
    re.compile(r"(?i)fivem://connect/([^\"'\s]+)"),
    re.compile(r"(?i)failed to connect to\s+([^\"'\s]+)\s+port\s+(\d{1,5})"),
    re.compile(r"(?i)server variables.*?\b((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\b"),
)
PROCESS_NAME_PATTERN = re.compile(
    r"(?i)^(?:fivem(?:_b\d+)?(?:_gtaprocess)?|citizenfx(?:\.exe)?|redm(?:_b\d+)?)$"
)
VALID_HOSTNAME_PATTERN = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def _strip_candidate(value):
    text = str(value or "").strip().strip("\"'")
    text = text.rstrip(".,;)]}>")
    if "?" in text:
        text = text.split("?", 1)[0]
    if "#" in text:
        text = text.split("#", 1)[0]
    return text


def normalize_endpoint(value):
    """Return a normalized host:port string, or None for non-endpoints."""

    text = _strip_candidate(value)
    if not text:
        return None

    # Values captured from a connect URI can still contain a path separator.
    if text.lower().startswith("fivem://connect/"):
        text = text.split("/", 3)[-1]
    elif text.lower().startswith(("http://", "https://")):
        try:
            from urllib.parse import urlsplit

            parsed = urlsplit(text)
            text = parsed.netloc
        except Exception:
            return None
    elif "/" in text:
        text = text.split("/", 1)[0]

    host = None
    port = None
    if text.startswith("["):
        closing = text.find("]")
        if closing <= 1 or closing + 1 >= len(text) or text[closing + 1] != ":":
            return None
        host = text[1:closing]
        port_text = text[closing + 2 :]
    else:
        if ":" not in text:
            return None
        host, port_text = text.rsplit(":", 1)

    host = host.strip().strip("[]").rstrip(".")
    if not host or not port_text.isdigit():
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not VALID_HOSTNAME_PATTERN.match(host):
            return None
        # A hostname is useful evidence too, but keep it lower-case for
        # deterministic candidate de-duplication.
        host = host.lower()

    if ":" in host:
        return "[%s]:%d" % (host, port)
    return "%s:%d" % (host, port)


def endpoint_parts(endpoint):
    text = str(endpoint or "")
    if text.startswith("["):
        closing = text.find("]")
        if closing > 0 and text[closing + 1 : closing + 2] == ":":
            return text[1:closing], int(text[closing + 2 :])
    host, port = text.rsplit(":", 1)
    return host, int(port)


def extract_endpoints_from_text(text, patterns):
    """Extract normalized endpoint candidates from a command line or log."""

    found = []
    seen = set()
    source_text = str(text or "")
    for pattern in patterns:
        for match in pattern.finditer(source_text):
            if match.lastindex == 2 and match.group(2).isdigit():
                raw = "%s:%s" % (match.group(1), match.group(2))
            else:
                raw = match.group(1)
            endpoint = normalize_endpoint(raw)
            if endpoint and endpoint not in seen:
                found.append(endpoint)
                seen.add(endpoint)
    return found


def is_fivem_process_name(name):
    normalized = str(name or "").strip()
    if not normalized:
        return False
    if normalized.lower().endswith(".exe"):
        normalized = normalized[:-4]
    if PROCESS_NAME_PATTERN.match(normalized):
        return True
    lowered = normalized.lower()
    return "citizenfx" in lowered or bool(re.match(r"^redm(?:_b\d+)?(?:_gtaprocess)?$", lowered))


def is_game_process_name(name):
    lowered = str(name or "").lower()
    return "gtaprocess" in lowered or "gameprocess" in lowered or "redm_" in lowered


def safe_process_attr(proc, attr, default=None):
    try:
        value = getattr(proc, attr)
        return value() if callable(value) else value
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return default


def collect_fivem_processes():
    """Collect FiveM processes and their readable metadata without cmdline output."""

    if psutil is None:
        raise RuntimeError("缺少 psutil，请在 dump-tool 环境执行 pip install psutil。")

    processes = {}
    # Query only the process name for the full process list.  Reading exe and
    # creation time for every Windows process can be slow or require extra
    # permissions; those attributes are fetched only for matching processes.
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            if not is_fivem_process_name(name):
                continue
            processes[int(info.get("pid") or proc.pid)] = {
                "proc": proc,
                "pid": int(info.get("pid") or proc.pid),
                "name": str(name),
                "exe": safe_process_attr(proc, "exe", "") or "",
                "create_time": safe_process_attr(proc, "create_time", None),
                "ppid": int(safe_process_attr(proc, "ppid", 0) or 0),
                "game": is_game_process_name(name),
                "cmdline": [],
                "cmdline_readable": False,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, TypeError, ValueError):
            continue

    # The game process often carries the connect URI, while the launcher owns
    # the log directory.  Include the immediate parent when it is available.
    for entry in list(processes.values()):
        proc = entry["proc"]
        try:
            parent = proc.parent()
            if parent and parent.pid not in processes:
                parent_name = parent.name() or ""
                if is_fivem_process_name(parent_name):
                    processes[parent.pid] = {
                        "proc": parent,
                        "pid": int(parent.pid),
                        "name": str(parent_name),
                        "exe": safe_process_attr(parent, "exe", "") or "",
                        "create_time": safe_process_attr(parent, "create_time", None),
                        "ppid": int(safe_process_attr(parent, "ppid", 0) or 0),
                        "game": is_game_process_name(parent_name),
                        "cmdline": [],
                        "cmdline_readable": False,
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            pass

    for entry in processes.values():
        try:
            entry["cmdline"] = list(entry["proc"].cmdline() or [])
            entry["cmdline_readable"] = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            entry["cmdline"] = []
    return list(processes.values())


def add_candidate(candidates, endpoint, source, score, entry=None, evidence="", observed_at=None):
    if not endpoint:
        return
    key = endpoint.casefold()
    item = {
        "address": endpoint,
        "source": source,
        "score": int(score),
        "pid": int(entry.get("pid")) if entry and entry.get("pid") else None,
        "process": str(entry.get("name")) if entry and entry.get("name") else None,
        "evidence": evidence,
        "observed_at": observed_at,
    }
    existing = candidates.get(key)
    if existing is None or (item["score"], item.get("observed_at") or 0) > (
        existing["score"], existing.get("observed_at") or 0
    ):
        candidates[key] = item


def scan_process_arguments(processes, candidates):
    for entry in processes:
        command_line = " ".join(str(value) for value in entry.get("cmdline") or [])
        for endpoint in extract_endpoints_from_text(command_line, PROCESS_CONNECT_PATTERNS):
            add_candidate(
                candidates,
                endpoint,
                "process-commandline",
                100 if entry.get("game") else 96,
                entry,
                "FiveM 进程启动参数",
                time.time(),
            )


def infer_log_dirs(processes, explicit_root=None, explicit_logs=None):
    paths = []
    if explicit_logs:
        paths.append(Path(explicit_logs).expanduser())
    if explicit_root:
        root = Path(explicit_root).expanduser()
        paths.extend([root / "logs", root.parent / "logs"])

    for entry in processes:
        exe = str(entry.get("exe") or "")
        if not exe:
            continue
        exe_path = Path(exe)
        ancestor = exe_path.parent
        for _ in range(6):
            paths.append(ancestor / "logs")
            # A launcher outside FiveM.app can still point at a sibling
            # FiveM.app directory, which is where CitizenFX logs live.
            paths.append(ancestor / "FiveM.app" / "logs")
            if ancestor.parent == ancestor:
                break
            ancestor = ancestor.parent

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        paths.extend(
            [
                Path(local_app_data) / "FiveM" / "FiveM.app" / "logs",
                Path(local_app_data) / "FiveM" / "logs",
            ]
        )

    result = []
    seen = set()
    for path in paths:
        try:
            key = str(path.resolve()).casefold()
        except OSError:
            key = str(path).casefold()
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        result.append(path)
    return result


def read_tail(path, max_bytes):
    with open(str(path), "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes), os.SEEK_SET)
        return handle.read().decode("utf-8", errors="replace")


def scan_recent_logs(processes, candidates, logs_dir=None, fivem_root=None, max_age=DEFAULT_LOG_MAX_AGE,
                     allow_stale=False):
    dirs = infer_log_dirs(processes, explicit_root=fivem_root, explicit_logs=logs_dir)
    if not dirs:
        return []

    now = time.time()
    process_start = [entry.get("create_time") for entry in processes if entry.get("create_time")]
    oldest_process_start = min(process_start) if process_start else None
    files = []
    for directory in dirs:
        try:
            files.extend(directory.glob("CitizenFX_log_*.log"))
        except OSError:
            continue
    files = sorted(set(files), key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)
    results = []
    for path in files[:DEFAULT_LOG_FILES]:
        try:
            mtime = path.stat().st_mtime
            if now - mtime > max_age:
                continue
            if not allow_stale and oldest_process_start and mtime < oldest_process_start - 300:
                continue
            text = read_tail(path, DEFAULT_LOG_TAIL_BYTES)
        except (OSError, UnicodeError):
            continue

        endpoints = extract_endpoints_from_text(text, LOG_CONNECT_PATTERNS)
        for endpoint in endpoints:
            # The newest log is the best file-level evidence.  A repeated
            # reconnect in the same file remains a current endpoint candidate.
            add_candidate(
                candidates,
                endpoint,
                "recent-citizenfx-log",
                86,
                None,
                "最近 CitizenFX 日志: %s" % path.name,
                mtime,
            )
            results.append({"file": str(path), "address": endpoint, "mtime": mtime})
    return results


def connection_remote_address(connection):
    remote = getattr(connection, "raddr", None)
    if not remote:
        return None
    try:
        host = remote[0]
        port = int(remote[1])
    except (IndexError, TypeError, ValueError):
        return None
    if not host or host in {"0.0.0.0", "::"} or not 1 <= port <= 65535:
        return None
    return normalize_endpoint("%s:%d" % (host, port))


def scan_network_connections(processes, candidates):
    for entry in processes:
        proc = entry["proc"]
        try:
            connection_method = getattr(proc, "net_connections", None) or getattr(proc, "connections", None)
            if connection_method is None:
                continue
            connections = connection_method(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, AttributeError):
            continue
        for connection in connections:
            endpoint = connection_remote_address(connection)
            if not endpoint:
                continue
            port = endpoint_parts(endpoint)[1]
            socket_type = getattr(connection, "type", None)
            is_udp = socket_type == socket.SOCK_DGRAM
            status = str(getattr(connection, "status", "") or "").upper()
            score = 55
            if entry.get("game"):
                score += 12
            if is_udp:
                score += 20
            if status == "ESTABLISHED":
                score += 10
            if port in GAME_PORT_HINTS:
                score += 8
            if port in WEB_PORTS:
                score -= 20
            protocol = "UDP" if is_udp else "TCP"
            evidence = "FiveM 进程网络连接 %s/%s" % (protocol, status or "unknown")
            add_candidate(candidates, endpoint, "process-network", score, entry, evidence, time.time())


def scan_process_memory(processes, candidates, timeout_seconds=45.0):
    """Search readable FiveM game memory for IPv4:port strings.

    This deliberately searches only endpoint-shaped strings.  It does not
    inspect or return token-shaped data.  The scan is bounded because a FiveM
    process can contain several gigabytes of committed memory.
    """

    if os.name != "nt":
        return {"supported": False, "scanned": False, "regions": 0, "bytes": 0, "timed_out": False}

    game_entries = [entry for entry in processes if entry.get("game")]
    if not game_entries:
        return {"supported": True, "scanned": False, "regions": 0, "bytes": 0, "timed_out": False}

    endpoint_pattern = re.compile(rb"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}(?!\d)")
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        dword = wintypes.DWORD
        size_t = ctypes.c_size_t
        void_p = ctypes.c_void_p

        class MemoryBasicInformation(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", void_p),
                ("AllocationBase", void_p),
                ("AllocationProtect", dword),
                ("RegionSize", size_t),
                ("State", dword),
                ("Protect", dword),
                ("Type", dword),
            ]

        open_process = kernel32.OpenProcess
        open_process.argtypes = [dword, wintypes.BOOL, dword]
        open_process.restype = wintypes.HANDLE
        query = kernel32.VirtualQueryEx
        query.argtypes = [wintypes.HANDLE, void_p, ctypes.POINTER(MemoryBasicInformation), size_t]
        query.restype = size_t
        read = kernel32.ReadProcessMemory
        read.argtypes = [wintypes.HANDLE, void_p, void_p, size_t, ctypes.POINTER(size_t)]
        read.restype = ctypes.wintypes.BOOL
        close = kernel32.CloseHandle
    except (AttributeError, OSError):
        return {"supported": False, "scanned": False, "regions": 0, "bytes": 0, "timed_out": False}

    process_query_information = 0x0400
    process_vm_read = 0x0010
    mem_commit = 0x1000
    page_guard = 0x100
    readable_protect = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    stats = {"supported": True, "scanned": False, "regions": 0, "bytes": 0, "timed_out": False}

    for entry in game_entries:
        if time.monotonic() >= deadline:
            stats["timed_out"] = True
            break
        pid = int(entry.get("pid") or 0)
        if pid <= 0:
            continue
        handle = open_process(process_query_information | process_vm_read, False, pid)
        if not handle:
            continue
        stats["scanned"] = True
        address = 0
        mbi = MemoryBasicInformation()
        carry = b""
        region_count = 0
        try:
            while query(handle, void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if time.monotonic() >= deadline:
                    stats["timed_out"] = True
                    break
                region_size = int(mbi.RegionSize or 0)
                protection = int(mbi.Protect or 0)
                if (
                    mbi.State == mem_commit
                    and region_size > 0
                    and not (protection & page_guard)
                    and (protection & readable_protect)
                ):
                    region_count += 1
                    if region_count > MEMORY_SCAN_MAX_REGIONS:
                        break
                    region_base = int(mbi.BaseAddress or 0)
                    offset = 0
                    while offset < region_size:
                        if time.monotonic() >= deadline:
                            stats["timed_out"] = True
                            break
                        read_size = min(MEMORY_CHUNK_SIZE, region_size - offset)
                        buffer = (ctypes.c_char * read_size)()
                        bytes_read = size_t()
                        if read(handle, void_p(region_base + offset), buffer, read_size, ctypes.byref(bytes_read)):
                            data = bytes(buffer)[: int(bytes_read.value)]
                            stats["bytes"] += len(data)
                            window = carry + data
                            for match in endpoint_pattern.finditer(window):
                                endpoint = normalize_endpoint(match.group().decode("ascii", "ignore"))
                                if endpoint:
                                    add_candidate(
                                        candidates,
                                        endpoint,
                                        "process-memory",
                                        82,
                                        entry,
                                        "FiveM 游戏进程内存中的 IP:端口字符串",
                                        time.time(),
                                    )
                            carry = window[-MEMORY_OVERLAP_SIZE:]
                        offset += read_size
                    if stats["timed_out"]:
                        break
                if region_size <= 0:
                    break
                address += region_size
        finally:
            try:
                close(handle)
            except Exception:
                pass
        stats["regions"] += region_count
        if stats["timed_out"]:
            break
    return stats


def load_dump_auto_module(dump_tool_dir):
    """Load dump-tool's token scanner without starting its CLI."""

    auto_path = Path(dump_tool_dir).expanduser() / "auto.py"
    if not auto_path.is_file():
        raise RuntimeError("找不到 dump-tool/auto.py，无法执行 Token 验证。")
    spec = importlib.util.spec_from_file_location("ck_dump_auto_probe", str(auto_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 dump-tool 的 Token 扫描模块。")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    return module


def verify_candidates(candidates, dump_tool_dir, limit=20, timeout_seconds=5.0, token=None):
    """Authenticate endpoint candidates with the current FiveM Token.

    Only the configuration response shape is retained.  The Token and response
    body are never written to the probe report.
    """

    ranked = sorted(
        candidates.values(),
        key=lambda item: (item.get("score", 0), item.get("observed_at") or 0),
        reverse=True,
    )[: max(1, int(limit))]
    result = {
        "status": "not-run",
        "token_found": False,
        "tested": [],
        "verified": None,
    }
    if not ranked:
        result["status"] = "no-candidates"
        return result

    try:
        if token is None:
            auto_module = load_dump_auto_module(dump_tool_dir)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                token = auto_module.get_token()
            if not token:
                raise RuntimeError("未找到当前 FiveM Token。")
            token = auto_module.normalize_token(token)
    except Exception as exc:
        result["status"] = "token-error"
        result["error"] = str(exc)
        return result

    result["status"] = "tested"
    result["token_found"] = True
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "X-CitizenFX-Token": token,
        "User-Agent": "CitizenFX/1",
    })
    try:
        for candidate in ranked:
            address = str(candidate.get("address") or "")
            try:
                host, port = endpoint_parts(address)
            except (TypeError, ValueError):
                continue
            host_for_url = "[%s]" % host if ":" in host and not host.startswith("[") else host
            tested = {
                "address": address,
                "source": candidate.get("source"),
                "score": candidate.get("score", 0),
                "status": "failed",
                "transport": None,
                "http_status": None,
                "resource_count": None,
                "reason": "未验证",
            }
            for scheme in ("https", "http"):
                url = "%s://%s:%d/client" % (scheme, host_for_url, port)
                response = None
                try:
                    response = session.post(
                        url,
                        data={"method": "getConfiguration"},
                        timeout=max(1.0, float(timeout_seconds)),
                    )
                    tested["http_status"] = int(response.status_code)
                    if response.status_code < 200 or response.status_code >= 300:
                        tested["reason"] = "HTTP %d" % response.status_code
                        continue
                    payload = response.json()
                    resources = payload.get("resources") if isinstance(payload, dict) else None
                    if not isinstance(resources, list):
                        tested["reason"] = "响应缺少 resources 数组"
                        continue
                    tested.update({
                        "status": "verified",
                        "transport": scheme,
                        "resource_count": len(resources),
                        "reason": "返回有效服务器资源配置",
                    })
                    result["tested"].append(tested)
                    if result["verified"] is None:
                        result["verified"] = {
                            "address": address,
                            "transport": scheme,
                            "resource_count": len(resources),
                            "source": candidate.get("source"),
                            "pid": candidate.get("pid"),
                            "process": candidate.get("process"),
                        }
                    break
                except requests.RequestException as exc:
                    tested["reason"] = type(exc).__name__
                except (ValueError, TypeError) as exc:
                    tested["reason"] = type(exc).__name__
                finally:
                    if response is not None:
                        response.close()
            else:
                result["tested"].append(tested)
    finally:
        session.close()
    if result["verified"] is not None:
        result["status"] = "verified"
    return result


def build_report(processes, candidates, log_hits, started_at, memory_scan=None, verification=None):
    ranked = sorted(
        candidates.values(),
        key=lambda item: (item.get("score", 0), item.get("observed_at") or 0),
        reverse=True,
    )
    selected = ranked[0] if ranked else None
    return {
        "tool": "fivem-connection-probe",
        "version": TOOL_VERSION,
        "status": "detected" if selected else "not-detected",
        "selected": selected,
        "candidates": ranked,
        "processes": [
            {
                "pid": entry["pid"],
                "name": entry["name"],
                "game_process": bool(entry.get("game")),
                "cmdline_readable": bool(entry.get("cmdline_readable")),
            }
            for entry in sorted(processes, key=lambda item: item["pid"])
        ],
        "log_hits": log_hits,
        "memory_scan": memory_scan or {"supported": False, "scanned": False},
        "verification": verification or {"status": "not-run"},
        "started_at": started_at,
    }


def run_probe(args):
    started_at = time.time()
    processes = collect_fivem_processes()
    candidates = {}
    scan_process_arguments(processes, candidates)
    # A log file by itself is not proof that a FiveM instance is currently
    # running.  Keep the probe focused on the current client, even when a
    # caller explicitly supplies an installation directory.
    log_hits = []
    if processes:
        log_hits = scan_recent_logs(
            processes,
            candidates,
            logs_dir=args.logs_dir,
            fivem_root=args.fivem_root,
            max_age=args.max_log_age,
            allow_stale=args.allow_stale_logs,
        )
    if processes and not args.no_network:
        scan_network_connections(processes, candidates)
    memory_scan = {"supported": False, "scanned": False, "regions": 0, "bytes": 0, "timed_out": False}
    strong_sources = {"process-commandline", "recent-citizenfx-log"}
    has_strong_candidate = any(item.get("source") in strong_sources for item in candidates.values())
    if processes and args.memory_scan and not has_strong_candidate:
        memory_scan = scan_process_memory(processes, candidates, timeout_seconds=args.memory_timeout)
    verification = {"status": "not-run"}
    if args.verify:
        verification = verify_candidates(
            candidates,
            dump_tool_dir=args.dump_tool_dir,
            limit=args.verify_limit,
            timeout_seconds=args.verify_timeout,
        )
    report = build_report(
        processes,
        candidates,
        log_hits,
        started_at,
        memory_scan=memory_scan,
        verification=verification,
    )
    if verification.get("verified"):
        verified = verification["verified"]
        report["status"] = "verified"
        report["selected"] = {
            "address": verified.get("address"),
            "source": verified.get("source"),
            "score": next(
                (
                    item.get("score", 0)
                    for item in candidates.values()
                    if item.get("address") == verified.get("address")
                ),
                0,
            ),
            "pid": verified.get("pid"),
            "process": verified.get("process"),
            "evidence": "已使用当前 FiveM Token 验证 getConfiguration",
            "transport": verified.get("transport"),
            "resource_count": verified.get("resource_count"),
        }
    return report


def print_human_report(report):
    print("FiveM 当前连接诊断工具 v%s" % report["version"])
    print("进程: %d 个" % len(report.get("processes") or []))
    if not report.get("processes"):
        print("结果: 未检测到正在运行的 FiveM 进程。")
        return
    selected = report.get("selected")
    if selected:
        print("结果: 已识别服务器地址 %s" % selected["address"])
        print("来源: %s | 置信分: %s" % (selected["source"], selected["score"]))
        if selected.get("pid"):
            print("进程: %s (PID %s)" % (selected.get("process") or "FiveM", selected["pid"]))
        print("证据: %s" % selected.get("evidence", ""))
    else:
        print("结果: 未找到当前服务器地址。")
    verification = report.get("verification") or {}
    if verification.get("status") == "verified" and verification.get("verified"):
        verified = verification["verified"]
        print(
            "验证: 已通过 Token 验证 %s（%s，资源 %s 个）"
            % (
                verified.get("address"),
                verified.get("transport"),
                verified.get("resource_count"),
            )
        )
    elif verification.get("status") == "token-error":
        print("验证: Token 扫描失败（未输出 Token 内容）")
    elif verification.get("status") not in ("not-run", "no-candidates"):
        print("验证: 未找到返回有效资源配置的候选地址")
    candidates = report.get("candidates") or []
    if candidates:
        print("候选地址:")
        for item in candidates:
            print(
                "  - %-22s 分数=%-3s 来源=%s%s"
                % (
                    item["address"],
                    item["score"],
                    item["source"],
                    (" | " + item["evidence"]) if item.get("evidence") else "",
                )
            )
    else:
        print("候选地址: 无")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="读取当前运行的 FiveM 服务器连接地址。")
    parser.add_argument("--json", action="store_true", help="输出 JSON，便于工具箱或脚本调用。")
    parser.add_argument("--fivem-root", default="", help="FiveM.app 目录；默认从进程路径和 LOCALAPPDATA 推断。")
    parser.add_argument("--logs-dir", default="", help="直接指定 CitizenFX 日志目录。")
    parser.add_argument("--max-log-age", type=float, default=DEFAULT_LOG_MAX_AGE, help="允许读取的日志最大年龄（秒）。")
    parser.add_argument("--allow-stale-logs", action="store_true", help="允许读取早于当前进程启动时间的日志，仅用于诊断。")
    parser.add_argument("--no-network", action="store_true", help="不读取进程网络连接，只检查参数和日志。")
    parser.add_argument("--memory-scan", dest="memory_scan", action="store_true", help="在其他来源没有候选地址时扫描 FiveM 游戏进程内存（默认开启）。")
    parser.add_argument("--no-memory-scan", dest="memory_scan", action="store_false", help="关闭内存地址扫描。")
    parser.add_argument("--memory-timeout", type=float, default=45.0, help="内存扫描最长时间（秒）。")
    parser.add_argument("--verify", action="store_true", help="使用当前 FiveM Token 验证候选地址的服务器配置。")
    parser.add_argument("--dump-tool-dir", default=str(Path(__file__).resolve().parent.parent / "dump-tool"), help="dump-tool 目录，用于调用现有 Token 扫描器。")
    parser.add_argument("--verify-limit", type=int, default=20, help="最多验证多少个候选地址。")
    parser.add_argument("--verify-timeout", type=float, default=5.0, help="每个协议请求的超时时间（秒）。")
    parser.set_defaults(memory_scan=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        report = run_probe(args)
    except Exception as exc:
        if args.json:
            print(json.dumps({"tool": "fivem-connection-probe", "status": "error", "error": str(exc)}, ensure_ascii=False))
        else:
            print("诊断失败: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human_report(report)
    return 0 if report.get("selected") else 1


if __name__ == "__main__":
    sys.exit(main())
