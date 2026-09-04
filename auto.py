import argparse
import base64
import ctypes
import ctypes.wintypes as wintypes
import errno
from fnmatch import fnmatchcase
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

import psutil
import requests
import urllib3
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

for _console_stream in (sys.stdout, sys.stderr):
    try:
        _console_stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

TOOL_VERSION = "1.1.14"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_MIN_FREE_GB = 5.0
BYTES_PER_GB = 1024 ** 3
DOWNLOAD_MAX_ATTEMPTS = 4
DOWNLOAD_RETRY_BASE_SECONDS = 1.0
DOWNLOAD_RETRY_MAX_SECONDS = 8.0
DOWNLOAD_RETRY_AFTER_MAX_SECONDS = 30.0
DOWNLOAD_RETRY_STATUS_CODES = {403, 404, 408, 409, 425, 429, 500, 502, 503, 504}
VERTEX_FIXER_CLI = SCRIPT_DIR / "FIXER" / "FivemDecryptFixer.Cli.exe"
VERTEX_FIX_EXTENSIONS = {".ydr", ".yft", ".ydd"}
VERTEX_FIX_DISCLAIMER = (
    "顶点修复不等于模型修复，不一定能 100% 修复模型，也不保证修复后的模型可以被 FiveM 加载。"
    "如需修复模型，可以进群找群主免费修复。"
)
GRANTS_CLK_DERIVE_URL = "https://grantsclk.ckcloud.de5.net/v1/derive"
GRANTS_CLK_REQUESTS_PER_MINUTE = 45
GRANTS_CLK_MIN_INTERVAL_SECONDS = 60.0 / GRANTS_CLK_REQUESTS_PER_MINUTE
GRANTS_CLK_MAX_ATTEMPTS = 3
STREAM_EXTENSIONS = {".yft", ".ytd", ".ydr", ".ydd", ".ybn", ".ymap", ".ytyp", ".ymf", ".awc"}
RSC_HEADERS = (b"RSC7", b"RSC8")
JAVA_MINIMUM_MAJOR = 8
JAVA_RECOMMENDED_MAJOR = 17

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_GUARD = 0x100

SIZE_T = ctypes.c_size_t
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", SIZE_T),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


if kernel32:
    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.restype = SIZE_T
    VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        SIZE_T,
    ]

    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.restype = wintypes.BOOL
    ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        SIZE_T,
        ctypes.POINTER(SIZE_T),
    ]


def print_external_line(prefix, value):
    message = f"{prefix}{value}"
    try:
        print(message, flush=True)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        safe_message = message.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe_message, flush=True)


def emit_progress(percent, stage, message):
    payload = {
        "percent": max(0, min(100, int(percent))),
        "stage": str(stage),
        "message": str(message),
    }
    print_external_line("", "CK_PROGRESS " + json.dumps(payload, ensure_ascii=False))


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def safe_name(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', "_", name)


def count_files(path):
    total = 0
    if not path or not os.path.isdir(path):
        return 0
    for _, _, files in os.walk(path):
        total += len(files)
    return total


def directory_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def create_vertex_fix_output_dir(output_dir):
    output_dir = Path(output_dir).resolve()
    base = output_dir.parent / f"{output_dir.name}_顶点修复"
    if not base.exists():
        return base

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for suffix in range(1000):
        candidate_name = f"{base.name}_{timestamp}"
        if suffix:
            candidate_name += f"-{suffix}"
        candidate = base.parent / candidate_name
        if not candidate.exists():
            return candidate
    raise RuntimeError("无法创建唯一的顶点修复输出目录。")


def run_vertex_fix(decrypt_resources, output_dir, output_guard=None):
    result = {
        "enabled": True,
        "status": "pending",
        "source_output": str(Path(output_dir).resolve()),
        "output": "",
        "resources_eligible": 0,
        "resources_copied": 0,
        "scanned_files": 0,
        "repaired_files": 0,
        "failed_files": 0,
        "exit_code": None,
        "warnings": [],
        "disclaimer": VERTEX_FIX_DISCLAIMER,
    }

    eligible = []
    for item in decrypt_resources or []:
        if not item.get("is_fxap") or item.get("status") != "decrypted":
            continue
        source = Path(item.get("output_dir") or "")
        if source.is_dir():
            eligible.append((item, source.resolve()))

    result["resources_eligible"] = len(eligible)
    if not eligible:
        result["status"] = "skipped"
        print("[顶点修复] 本次没有已解密的 FXAP 资源，已跳过顶点修复。")
        return result

    if not VERTEX_FIXER_CLI.is_file():
        raise RuntimeError(f"缺少顶点修复命令行工具: {VERTEX_FIXER_CLI}")

    fixed_root = create_vertex_fix_output_dir(output_dir)
    model_bytes = 0
    for _, source in eligible:
        for path in source.rglob("*"):
            if path.is_file() and path.suffix.lower() in VERTEX_FIX_EXTENSIONS:
                try:
                    model_bytes += path.stat().st_size
                except OSError:
                    pass
    required_bytes = sum(directory_size(source) for _, source in eligible) + model_bytes
    if output_guard:
        output_guard.check(required_bytes=required_bytes, force=True)

    fixed_root.mkdir(parents=True, exist_ok=False)
    result["output"] = str(fixed_root)
    print(f"[顶点修复] 原解密目录保持不变: {Path(output_dir).resolve()}")
    print(f"[顶点修复] 正在复制 {len(eligible)} 个 FXAP 资源的完整目录到: {fixed_root}")

    for index, (item, source) in enumerate(eligible, start=1):
        destination = fixed_root / source.name
        if destination.exists():
            raise RuntimeError(f"顶点修复副本目录冲突: {destination}")
        shutil.copytree(source, destination)
        result["resources_copied"] += 1
        print(f"[顶点修复] 已复制完整资源 {index}/{len(eligible)}: {item.get('name', source.name)}")

    work_root = Path(tempfile.mkdtemp(prefix=".ck_vertex_fix_work-", dir=str(fixed_root.parent)))
    model_file_count = 0
    try:
        for _, source in eligible:
            destination = fixed_root / source.name
            for model_path in destination.rglob("*"):
                if not model_path.is_file() or model_path.suffix.lower() not in VERTEX_FIX_EXTENSIONS:
                    continue
                relative = model_path.relative_to(fixed_root)
                work_path = work_root / relative
                work_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(model_path, work_path)
                model_file_count += 1

        print(f"[顶点修复] 已隔离 {model_file_count} 个 .ydr/.yft/.ydd 文件；其他文件不会交给修复器。")
        print(f"[顶点修复提示] {VERTEX_FIX_DISCLAIMER}")
        proc = subprocess.run(
            [str(VERTEX_FIXER_CLI), "fix-models", str(work_root)],
            cwd=str(VERTEX_FIXER_CLI.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

        for repaired_path in work_root.rglob("*"):
            if repaired_path.is_file() and repaired_path.suffix.lower() in VERTEX_FIX_EXTENSIONS:
                destination = fixed_root / repaired_path.relative_to(work_root)
                shutil.copy2(repaired_path, destination)
    finally:
        if work_root.exists():
            shutil.rmtree(work_root, ignore_errors=True)
    result["exit_code"] = int(proc.returncode)
    combined_lines = []
    for text in (proc.stdout, proc.stderr):
        for line in (text or "").splitlines():
            if line.strip():
                combined_lines.append(line.rstrip())
                print_external_line("[顶点修复] ", line.rstrip())

    summary_pattern = re.compile(r"\[MODEL\]\s+scanned=(\d+),\s*repaired=(\d+),\s*failed=(\d+)")
    for line in reversed(combined_lines):
        match = summary_pattern.search(line)
        if match:
            result["scanned_files"] = int(match.group(1))
            result["repaired_files"] = int(match.group(2))
            result["failed_files"] = int(match.group(3))
            break

    if proc.returncode == 0:
        result["status"] = "success"
    elif result["repaired_files"] > 0 or result["resources_copied"] > 0:
        result["status"] = "partial"
        result["warnings"].append(
            f"顶点修复部分失败：扫描 {result['scanned_files']}，成功处理 {result['repaired_files']}，"
            f"失败 {result['failed_files']}，退出码 {proc.returncode}。"
        )
    else:
        result["status"] = "failed"
        detail = next((line for line in reversed(combined_lines) if "ERROR" in line or "FATAL" in line), "")
        result["warnings"].append(detail or f"顶点修复工具退出码: {proc.returncode}")

    return result


def mask_token(token):
    if not token:
        return ""
    if len(token) <= 12:
        return token[:3] + "***"
    return token[:8] + "..." + token[-4:]


def normalize_token(value):
    text = str(value or "")
    prefix = "X-CitizenFX-Token:"
    if text.lower().startswith(prefix.lower()):
        text = text[len(prefix) :]

    text = re.split(r"[\x00\r\n]", text, maxsplit=1)[0].strip()
    if not text:
        raise RuntimeError("扫描到的 FiveM token 为空，请重新进入服务器后再试。")
    if len(text) > 512 or not re.fullmatch(r"[!-~]+", text):
        raise RuntimeError("FiveM token 包含空格、控制字符或其他非法字符，请重新进入服务器后再试。")
    return text


def extract_token_from_memory(data, marker=b"X-CitizenFX-Token: "):
    search_from = 0
    while True:
        marker_index = data.find(marker, search_from)
        if marker_index == -1:
            return None

        value_start = marker_index + len(marker)
        value_end = min(len(data), value_start + 512)
        for delimiter in (b"\x00", b"\r", b"\n"):
            delimiter_index = data.find(delimiter, value_start, value_end)
            if delimiter_index != -1:
                value_end = min(value_end, delimiter_index)

        candidate = data[value_start:value_end].decode("ascii", errors="ignore")
        try:
            return normalize_token(candidate)
        except RuntimeError:
            search_from = value_start


def get_file_hash(file_data):
    if not file_data:
        return ""
    if isinstance(file_data, str):
        return file_data
    if isinstance(file_data, dict):
        return file_data.get("hash", "")
    return ""


def encode_file_path(file_name):
    return "/".join(
        quote(segment, safe="")
        for segment in str(file_name).replace("\\", "/").split("/")
        if segment
    )


def resource_pattern_matches(resource_name, pattern):
    name = str(resource_name or "")
    expression = str(pattern or "").strip()
    if not expression:
        return False
    if name.casefold() == expression.casefold():
        return True
    return fnmatchcase(name.casefold(), expression.casefold())


def resolve_resource_selection(resources, choice):
    exact_names = isinstance(choice, (list, tuple, set))
    if exact_names:
        tokens = [str(value).strip() for value in choice if str(value).strip()]
    else:
        tokens = [value.strip() for value in str(choice or "").split(",") if value.strip()]

    selected = []
    selected_indexes = set()
    unmatched = []
    for token in tokens:
        matches = []
        if exact_names:
            matches = [
                index for index, resource in enumerate(resources)
                if str(resource.get("name", "")).casefold() == token.casefold()
            ]
        elif token.casefold() == "all":
            matches = list(range(len(resources)))
        elif token.isdigit():
            index = int(token)
            if 0 <= index < len(resources):
                matches = [index]
        else:
            exact_matches = [
                index for index, resource in enumerate(resources)
                if str(resource.get("name", "")).casefold() == token.casefold()
            ]
            matches = exact_matches or [
                index for index, resource in enumerate(resources)
                if resource_pattern_matches(resource.get("name", ""), token)
            ]

        if not matches:
            unmatched.append(token)
            continue
        for index in matches:
            if index in selected_indexes:
                continue
            selected_indexes.add(index)
            selected.append(resources[index])
    return selected, unmatched


def load_resource_selection_file(file_path):
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"Resource selection file does not exist: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise RuntimeError(f"Resource selection file is too large: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise RuntimeError(f"Unable to read resource selection file {path}: {exc}") from exc
    values = payload.get("resources") if isinstance(payload, dict) else payload
    # Toolbox versions before the single-selection fix serialized one resource as
    # a JSON string. Accept that legacy object shape while keeping other invalid
    # selection-file shapes rejected.
    if isinstance(payload, dict) and isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        raise RuntimeError("Resource selection file must contain a resources array")
    names = [value.strip() for value in values if isinstance(value, str) and value.strip()]
    if not names:
        raise RuntimeError("Resource selection file does not contain any resource names")
    if len(names) > 10000:
        raise RuntimeError("Resource selection file contains too many resource names")
    return names


def load_failed_download_retry_report(file_path):
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"补充下载报告不存在: {path}")
    if path.stat().st_size > 50 * 1024 * 1024:
        raise RuntimeError(f"补充下载报告过大: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise RuntimeError(f"无法读取补充下载报告 {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("command") != "server-dump":
        raise RuntimeError("补充下载只接受 dump-tool 生成的 server-dump JSON 报告。")

    target = str(payload.get("target") or "").strip()
    output = str(payload.get("output") or "").strip()
    if not target or not output:
        raise RuntimeError("补充下载报告缺少目标服务器或原输出目录。")

    files_by_resource = {}
    retry_meta = payload.get("retry_failed") or {}
    for resource_name, file_names in (retry_meta.get("remaining_by_resource") or {}).items():
        name = str(resource_name or "").strip()
        if not name:
            continue
        names = files_by_resource.setdefault(name, [])
        for value in file_names or []:
            file_name = str(value or "").strip()
            if file_name and file_name not in names:
                names.append(file_name)
    for item in payload.get("dump_resources") or []:
        if not isinstance(item, dict):
            continue
        resource_name = str(item.get("name") or "").strip()
        if not resource_name:
            continue
        names = files_by_resource.setdefault(resource_name, [])
        for failure in item.get("failed_downloads") or []:
            if isinstance(failure, dict):
                file_name = str(failure.get("file") or "").strip()
                if file_name and file_name not in names:
                    names.append(file_name)
        for pending in item.get("retry_pending_files") or []:
            file_name = str(pending or "").strip()
            if file_name and file_name not in names:
                names.append(file_name)

    files_by_resource = {name: files for name, files in files_by_resource.items() if files}
    if not files_by_resource:
        raise RuntimeError("该报告没有可补充下载的失败文件。")

    fxap_state = {}
    for item in (payload.get("decrypt_resources") or []) + (payload.get("raw_resources") or []):
        if isinstance(item, dict) and item.get("name"):
            fxap_state[str(item["name"])] = bool(item.get("is_fxap"))

    scope = payload.get("scope") or {}
    raw_mode = bool(scope.get("rawResourcePreservation")) or scope.get("fxapDecrypt") is False
    return {
        "source_report": str(path),
        "target": target,
        "output": str(Path(output).expanduser().resolve()),
        "raw_mode": raw_mode,
        "files_by_resource": files_by_resource,
        "resource_is_fxap": fxap_state,
        "requested_files": sum(len(files) for files in files_by_resource.values()),
    }


def print_warning(message):
    print_external_line("[警告] ", message)


def print_error(message):
    print_external_line("[错误] ", message)


class DiskSpaceError(RuntimeError):
    pass


class ResourceSelectionCancelled(RuntimeError):
    pass


def format_gb(value):
    return round(max(0, int(value)) / BYTES_PER_GB, 2)


def is_disk_full_error(exc):
    if not isinstance(exc, OSError):
        return False
    if getattr(exc, "errno", None) == errno.ENOSPC or getattr(exc, "winerror", None) == 112:
        return True
    text = str(exc).lower()
    return "no space left on device" in text or "磁盘空间不足" in text


class DiskSpaceGuard:
    def __init__(self, path, min_free_gb=DEFAULT_MIN_FREE_GB, label="磁盘"):
        self.path = Path(path).resolve()
        self.label = str(label)
        self.reserve_bytes = max(BYTES_PER_GB, int(float(min_free_gb) * BYTES_PER_GB))
        self._lock = threading.Lock()
        self._last_check = 0.0
        self._last_free = None

    def check(self, required_bytes=0, force=False):
        required_bytes = max(0, int(required_bytes or 0))
        with self._lock:
            now = time.monotonic()
            if force or self._last_free is None or now - self._last_check >= 0.5:
                usage = shutil.disk_usage(str(self.path))
                self._last_free = int(usage.free)
                self._last_check = now
            free_bytes = int(self._last_free)

        required_total = self.reserve_bytes + required_bytes
        if free_bytes < required_total:
            raise DiskSpaceError(
                f"{self.label}空间不足：当前剩余 {format_gb(free_bytes)} GB，"
                f"继续操作至少需要保留 {format_gb(required_total)} GB。路径: {self.path}"
            )
        return {
            "path": str(self.path),
            "free_bytes": free_bytes,
            "free_gb": format_gb(free_bytes),
            "minimum_free_gb": format_gb(self.reserve_bytes),
        }

    def raise_write_error(self, exc):
        try:
            self.check(force=True)
        except DiskSpaceError as space_exc:
            raise space_exc from exc
        raise DiskSpaceError(
            f"{self.label}写入失败，磁盘或配额空间不足。路径: {self.path}；系统错误: {exc}"
        ) from exc


def create_work_dir(temp_base, output_dir):
    output_dir = Path(output_dir).resolve()
    if temp_base:
        base = Path(temp_base).expanduser()
        if not base.is_absolute():
            base = output_dir.parent / base
    else:
        base = output_dir.parent
    base = base.resolve()
    base.mkdir(parents=True, exist_ok=True)

    run_name = f"_ck_dump_temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
    work_dir = base / run_name
    work_dir.mkdir(parents=True, exist_ok=False)
    return work_dir


def parse_java_major(version_text):
    text = (version_text or "").strip()
    match = re.search(r'(?i)\bversion\s+["\']?(\d+)(?:\.(\d+))?', text)
    if not match:
        match = re.search(r'(?i)\b(?:openjdk|java)\s+["\']?(\d+)(?:\.(\d+))?', text)
    if not match:
        return None
    first = int(match.group(1))
    second = int(match.group(2) or 0)
    return second if first == 1 else first


def java_candidates(configured_path=""):
    def expand_candidate(value):
        value = os.path.expandvars(os.path.expanduser((value or "").strip().strip('"')))
        if not value:
            return []
        path = Path(value)
        if path.is_file() or path.name.lower() in ("java.exe", "java"):
            return [str(path.resolve())]
        names = ["java.exe", "java"]
        results = []
        for name in names:
            results.append(str(path / "bin" / name))
            results.append(str(path / name))
        return results

    if configured_path:
        return expand_candidate(configured_path)

    candidates = []
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        candidates.extend(expand_candidate(java_home))
    path_java = shutil.which("java")
    if path_java:
        candidates.append(path_java)
    return candidates


def probe_java_executable(java_path):
    candidate = os.path.abspath(java_path)
    if not os.path.isfile(candidate):
        return {"ok": False, "path": candidate, "reason": "java 可执行文件不存在。"}

    try:
        proc = subprocess.run(
            [candidate, "-version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10,
        )
    except Exception as exc:
        return {"ok": False, "path": candidate, "reason": f"无法启动 java -version: {exc}"}

    version_text = "\n".join(part for part in [proc.stderr, proc.stdout] if part).strip()
    version_line = next((line.strip() for line in version_text.splitlines() if line.strip()), "")
    if proc.returncode != 0:
        detail = version_line or f"退出码 {proc.returncode}"
        return {"ok": False, "path": candidate, "reason": f"java -version 执行失败: {detail}"}

    major = parse_java_major(version_text)
    if major is None:
        return {"ok": False, "path": candidate, "reason": f"无法识别 Java 版本: {version_line or '无版本输出'}"}
    if major < JAVA_MINIMUM_MAJOR:
        return {
            "ok": False,
            "path": candidate,
            "version": version_line,
            "major": major,
            "reason": f"Java {major} 版本过低，需要 Java {JAVA_MINIMUM_MAJOR} 或更高版本，推荐 Java {JAVA_RECOMMENDED_MAJOR}。",
        }
    return {
        "ok": True,
        "path": candidate,
        "version": version_line,
        "major": major,
        "minimum_major": JAVA_MINIMUM_MAJOR,
        "recommended_major": JAVA_RECOMMENDED_MAJOR,
    }


def resolve_java_executable(configured_path=""):
    candidates = java_candidates(configured_path)
    failures = []
    seen = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        info = probe_java_executable(candidate)
        if info.get("ok"):
            return info
        if os.path.exists(candidate) or configured_path:
            failures.append(info.get("reason") or f"Java 不可用: {candidate}")

    if configured_path:
        detail = failures[0] if failures else "选择的位置中没有找到 java.exe。"
        raise RuntimeError(
            f"所选 Java 环境不可用: {configured_path}。{detail} "
            f"请安装 Java {JAVA_MINIMUM_MAJOR} 或更高版本（推荐 Java {JAVA_RECOMMENDED_MAJOR}），或重新选择 Java 目录。"
        )
    detail = f" 检测详情: {failures[0]}" if failures else ""
    raise RuntimeError(
        f"未检测到可用 Java，unluac54.jar 无法运行。请安装 Java {JAVA_MINIMUM_MAJOR} 或更高版本"
        f"（推荐 Java {JAVA_RECOMMENDED_MAJOR}），或使用 --java 指定 Java 目录/java.exe。{detail}"
    )


def direct_server_address(value):
    text = (value or "").strip()
    if not text:
        return None

    try:
        parsed = urlparse(text if re.match(r"^https?://", text, re.I) else "//" + text)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            host_ip = str(ipaddress.ip_address(host))
            return f"{host_ip}:{port}" if 1 <= int(port) <= 65535 else None
    except ValueError:
        pass

    candidate = re.sub(r"^https?://", "", text, flags=re.I).rstrip("/")
    match = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", candidate)
    if not match:
        return None

    try:
        host = str(ipaddress.ip_address(match.group(1)))
        port = int(match.group(2))
    except ValueError:
        return None
    return f"{host}:{port}" if 1 <= port <= 65535 else None


def find_fivem_process():
    pattern = re.compile(r"FiveM(_b\d+)?_GTAProcess", re.IGNORECASE)
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            name = proc.info.get("name") or ""
            if pattern.match(name):
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def get_token():
    if not kernel32:
        raise RuntimeError("自动扫描 token 只能在 Windows 上使用。")

    proc = find_fivem_process()
    if not proc:
        raise RuntimeError("未找到 FiveM 进程，请先进入目标服务器。")

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    if not handle:
        raise RuntimeError("无法打开 FiveM 进程，请尝试以管理员身份运行。")

    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    try:
        while VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if (
                mbi.State == MEM_COMMIT
                and (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY))
                and not (mbi.Protect & PAGE_GUARD)
            ):
                if mbi.RegionSize > 64 * 1024 * 1024:
                    address += mbi.RegionSize
                    continue

                buffer = (ctypes.c_char * mbi.RegionSize)()
                bytes_read = SIZE_T()

                if ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                    data = bytes(buffer)[: bytes_read.value]
                    token = extract_token_from_memory(data)
                    if token:
                        return token

            if mbi.RegionSize <= 0:
                break
            address += mbi.RegionSize
    finally:
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass

    return None


def server_base_urls(value, address):
    text = (value or "").strip()
    scheme_match = re.match(r"^(https?)://", text, re.I)
    if scheme_match:
        return [f"{scheme_match.group(1).lower()}://{address}"]
    return [f"https://{address}", f"http://{address}"]


def resolve_server_endpoint(target):
    direct = direct_server_address(target)
    if direct:
        base_urls = server_base_urls(target, direct)
        if len(base_urls) == 1:
            print(f"[地址] 使用直连服务器地址: {base_urls[0]}")
        else:
            print(f"[地址] 使用直连服务器地址: {direct}（自动尝试 HTTPS/HTTP）")
        return {"address": direct, "base_urls": base_urls}

    link = (target or "").strip()
    if not link:
        raise RuntimeError("目标地址为空。")
    if not re.match(r"^https?://", link, re.I):
        link = "https://" + link

    try:
        res = requests.get(link, timeout=15, allow_redirects=True)
        res.raise_for_status()
        header = res.headers.get("x-citizenfx-url")
        if not header:
            raise RuntimeError("响应中没有 x-citizenfx-url，无法解析服务器真实地址。")

        direct = direct_server_address(header)

        cleaned = re.sub(r"^https?://", "", header.strip(), flags=re.I).rstrip("/")
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})", cleaned)
        if match:
            direct = direct_server_address(match.group(1))

        if direct:
            base_urls = server_base_urls(header, direct)
            print(f"[地址] 已从 cfx.re 解析到服务器: {base_urls[0]}")
            return {"address": direct, "base_urls": base_urls}

        raise RuntimeError(f"解析到的服务器地址无效: {header}")
    except Exception as exc:
        raise RuntimeError(f"从 {link} 解析服务器地址失败: {exc}") from exc


def get_ip_from_cfx(target):
    return resolve_server_endpoint(target)["address"]


class FiveMDumper:
    def __init__(
        self,
        base_url,
        token,
        max_workers=10,
        work_guard=None,
        keep_temp=False,
        fallback_base_urls=None,
        retry_files_by_resource=None,
        include_decrypt_prerequisites=False,
        retry_resource_is_fxap=None,
    ):
        candidates = [base_url] + list(fallback_base_urls or [])
        self.base_urls = []
        for candidate in candidates:
            normalized = str(candidate or "").strip().rstrip("/")
            if normalized and normalized not in self.base_urls:
                self.base_urls.append(normalized)
        if not self.base_urls:
            raise RuntimeError("服务器连接地址为空。")
        self.base_url = self.base_urls[0]
        self.token = normalize_token(token)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"X-CitizenFX-Token": self.token, "User-Agent": "CitizenFX/1"})
        self.max_workers = max_workers
        self.work_guard = work_guard
        self.keep_temp = bool(keep_temp)
        self.retry_files_by_resource = None
        if retry_files_by_resource is not None:
            self.retry_files_by_resource = {
                str(resource_name): {
                    str(file_name).replace("\\", "/").casefold(): str(file_name).replace("\\", "/")
                    for file_name in file_names
                }
                for resource_name, file_names in retry_files_by_resource.items()
            }
        self.include_decrypt_prerequisites = bool(include_decrypt_prerequisites)
        self.retry_resource_is_fxap = {
            str(resource_name): bool(is_fxap)
            for resource_name, is_fxap in (retry_resource_is_fxap or {}).items()
        }
        self.unmatched_retry_resources = []
        self.summary = {
            "resources_total": 0,
            "resources_selected": 0,
            "downloaded_files": 0,
            "download_retried_files": 0,
            "download_retry_attempts": 0,
            "download_retry_recovered": 0,
            "failed_downloads": 0,
            "retry_requested_files": 0,
            "retry_recovered_files": 0,
            "retry_remaining_files": 0,
            "retry_prerequisite_files": 0,
            "failed_files": 0,
            "rpf_unpacked": 0,
            "warnings": 0,
            "errors": 0,
        }
        self.resource_reports = []

    def warn(self, item, message):
        self.summary["warnings"] += 1
        if item is not None:
            item["warnings"].append(message)
        print_warning(message)

    def error(self, item, message):
        self.summary["errors"] += 1
        if item is not None:
            item["errors"].append(message)
        print_error(message)

    def xor_bytes(self, data: bytes) -> bytes:
        key = bytes([0x69] * 16)
        return bytes(b ^ key[i % 16] for i, b in enumerate(data[:32]))

    def get_configuration(self, save_grants=True):
        emit_progress(22, "server_config", "正在向服务器请求资源配置。")
        data = {"method": "getConfiguration"}
        js = None
        for index, base_url in enumerate(self.base_urls):
            self.base_url = base_url
            url = f"{self.base_url}/client"
            try:
                resp = self.session.post(url, data=data, timeout=30)
                resp.raise_for_status()
                js = resp.json()
                break
            except requests.exceptions.HTTPError:
                raise
            except requests.exceptions.RequestException as exc:
                if index + 1 >= len(self.base_urls):
                    raise
                next_base_url = self.base_urls[index + 1]
                print_warning(f"{base_url} 连接失败，正在改用 {next_base_url}：{exc}")

        if js is None:
            raise RuntimeError("服务器没有返回有效配置。")

        if save_grants:
            if self.work_guard:
                self.work_guard.check(required_bytes=1024 * 1024, force=True)
            os.makedirs("Resources", exist_ok=True)
            with open("Resources/Grants.txt", "w", encoding="utf-8") as f:
                f.write(js.get("grants_token", ""))
        resources = js.get("resources", []) or []
        self.summary["resources_total"] = len(resources)
        print(f"[配置] 服务器返回 {len(resources)} 个资源。")
        return resources

    def _download_retry_delay(self, response, attempt):
        if response is not None:
            retry_after = str(response.headers.get("Retry-After", "") or "").strip()
            try:
                if retry_after:
                    return min(DOWNLOAD_RETRY_AFTER_MAX_SECONDS, max(0.0, float(retry_after)))
            except (TypeError, ValueError):
                pass
        base_delay = DOWNLOAD_RETRY_BASE_SECONDS * (2 ** max(0, attempt - 1))
        jittered_delay = base_delay * random.uniform(0.8, 1.2)
        return min(DOWNLOAD_RETRY_MAX_SECONDS, jittered_delay)

    def _download_failure(self, file_name, attempts, error, status_code=None):
        return {
            "path": None,
            "file": file_name,
            "bytes": 0,
            "attempts": int(attempts),
            "retries": max(0, int(attempts) - 1),
            "status_code": status_code,
            "failure_stage": "download",
            "error": str(error),
        }

    def download_and_decrypt(self, url, key, iv, out_path, file_name, resource_name=""):
        encrypted = None
        attempts = 0
        status_code = None
        retryable_exceptions = (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ContentDecodingError,
        )

        for attempt in range(1, DOWNLOAD_MAX_ATTEMPTS + 1):
            attempts = attempt
            status_code = None
            response = None
            try:
                response = self.session.get(url, timeout=(15, 60))
                status_code = int(response.status_code)
                if 200 <= status_code < 300:
                    encrypted = response.content
                    break

                reason = str(response.reason or "HTTP 请求失败").strip()
                error = f"HTTP {status_code} {reason}".strip()
                if status_code not in DOWNLOAD_RETRY_STATUS_CODES or attempt >= DOWNLOAD_MAX_ATTEMPTS:
                    return self._download_failure(file_name, attempts, error, status_code)

                delay = self._download_retry_delay(response, attempt)
                print_warning(
                    f"[下载重试] {resource_name}/{file_name} 第 {attempt}/{DOWNLOAD_MAX_ATTEMPTS} 次请求返回 "
                    f"HTTP {status_code}，{delay:.1f} 秒后重试。"
                )
            except retryable_exceptions as exc:
                error = f"{type(exc).__name__}: {exc}"
                if attempt >= DOWNLOAD_MAX_ATTEMPTS:
                    return self._download_failure(file_name, attempts, error, status_code)
                delay = self._download_retry_delay(None, attempt)
                print_warning(
                    f"[下载重试] {resource_name}/{file_name} 第 {attempt}/{DOWNLOAD_MAX_ATTEMPTS} 次请求异常："
                    f"{error}；{delay:.1f} 秒后重试。"
                )
            except requests.exceptions.RequestException as exc:
                return self._download_failure(file_name, attempts, f"{type(exc).__name__}: {exc}", status_code)
            except Exception as exc:
                return self._download_failure(file_name, attempts, f"{type(exc).__name__}: {exc}", status_code)
            finally:
                if response is not None:
                    response.close()

            time.sleep(delay)

        if encrypted is None:
            return self._download_failure(file_name, attempts, "服务器没有返回文件内容", status_code)

        try:
            try:
                cipher = ChaCha20.new(key=key, nonce=iv)
                dec = cipher.decrypt(encrypted)
            except Exception:
                try:
                    cipher = ChaCha20.new(key=key, nonce=iv[:8])
                    dec = cipher.decrypt(encrypted)
                except Exception as exc:
                    return {
                        "path": None,
                        "file": file_name,
                        "attempts": attempts,
                        "retries": max(0, attempts - 1),
                        "status_code": status_code,
                        "failure_stage": "decrypt",
                        "error": f"ChaCha20 解密失败: {exc}",
                    }

            if out_path.lower().endswith(".rpf") and not dec.startswith(b"RPF"):
                print_warning(f"{file_name} 的 RPF 文件头不完整，继续保存并尝试后续处理。")

            try:
                if self.work_guard:
                    self.work_guard.check(required_bytes=len(dec))
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(dec)
                return {
                    "path": out_path,
                    "file": file_name,
                    "bytes": len(dec),
                    "attempts": attempts,
                    "retries": max(0, attempts - 1),
                    "status_code": status_code,
                    "failure_stage": "",
                    "error": "",
                }
            except DiskSpaceError:
                raise
            except OSError as exc:
                if is_disk_full_error(exc) and self.work_guard:
                    self.work_guard.raise_write_error(exc)
                return {
                    "path": None,
                    "file": file_name,
                    "attempts": attempts,
                    "retries": max(0, attempts - 1),
                    "status_code": status_code,
                    "failure_stage": "write",
                    "error": f"写入文件失败: {exc}",
                }
            except Exception as exc:
                return {
                    "path": None,
                    "file": file_name,
                    "attempts": attempts,
                    "retries": max(0, attempts - 1),
                    "status_code": status_code,
                    "failure_stage": "write",
                    "error": f"写入文件失败: {exc}",
                }
        except DiskSpaceError:
            raise
        except Exception as exc:
            return {
                "path": None,
                "file": file_name,
                "attempts": attempts,
                "retries": max(0, attempts - 1),
                "status_code": status_code,
                "failure_stage": "process",
                "error": f"文件处理失败: {exc}",
            }

    def unpack_rpf(self, rpf_path, out_dir, item):
        unpacker = str((SCRIPT_DIR / "Bin" / "Unpacker.exe").resolve())
        rpf_path = os.path.abspath(rpf_path)
        out_dir = os.path.abspath(out_dir)

        if not os.path.exists(unpacker):
            self.warn(item, f"未找到 Bin/Unpacker.exe，跳过 RPF 解包: {os.path.basename(rpf_path)}")
            return False

        if self.work_guard:
            self.work_guard.check(force=True)
        os.makedirs(out_dir, exist_ok=True)
        try:
            proc = subprocess.run(
                [unpacker, rpf_path, out_dir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if proc.stdout.strip():
                print(proc.stdout.strip())
            if proc.stderr.strip():
                print("[Unpacker stderr] " + proc.stderr.strip())
            if self.work_guard:
                self.work_guard.check(force=True)

            extracted = "Extraído:" in proc.stdout or "Extracted:" in proc.stdout or proc.returncode == 0
            if extracted:
                print(f"[解包完成] {os.path.basename(rpf_path)} -> {out_dir}")
                self.summary["rpf_unpacked"] += 1
                item["rpf_unpacked"] += 1
                self.print_resource_summary(out_dir)
                return True

            self.warn(item, f"RPF 解包失败: {os.path.basename(rpf_path)}，退出码 {proc.returncode}。")
            return False
        except DiskSpaceError:
            raise
        except Exception as exc:
            self.warn(item, f"RPF 解包异常: {os.path.basename(rpf_path)}，{exc}")
            return False

    def print_resource_summary(self, out_dir):
        try:
            manifest_path = os.path.join(out_dir, "fxmanifest.lua")
            stream_dir = os.path.join(out_dir, "stream")
            print("[资源摘要]")
            print(f"路径: {out_dir}")
            if os.path.exists(manifest_path):
                print(" - fxmanifest.lua: 已找到")
            if os.path.isdir(stream_dir):
                stream_files = os.listdir(stream_dir)
                detail = ", ".join(stream_files) if stream_files else "无"
                print(f" - stream 文件: {detail}")
            for fname in os.listdir(out_dir):
                if fname != "stream":
                    print(f" - {fname}")
        except Exception as exc:
            print_warning(f"显示资源摘要失败: {exc}")

    def fetch_resource(self, res, index, total):
        resource_name = res.get("name", f"resource_{index}")
        res_name = safe_name(resource_name)
        if self.work_guard:
            self.work_guard.check(force=True)
        retry_lookup = None if self.retry_files_by_resource is None else self.retry_files_by_resource.get(resource_name, {})
        retry_mode = retry_lookup is not None
        item = {
            "name": resource_name,
            "safe_name": res_name,
            "status": "pending",
            "files_total": 0,
            "downloaded_files": 0,
            "download_retried_files": 0,
            "download_retry_attempts": 0,
            "download_retry_recovered": 0,
            "failed_downloads": [],
            "retry_mode": retry_mode,
            "retry_requested_files": list(retry_lookup.values()) if retry_mode else [],
            "retry_recovered_files": [],
            "retry_pending_files": [],
            "retry_prerequisite_files": [],
            "retry_prerequisite_failed": False,
            "failed_files": 0,
            "rpf_unpacked": 0,
            "warnings": [],
            "errors": [],
        }

        try:
            uri = base64.b64decode(res["uri"].split("#")[1])
            xored_key = uri[19:]
            iv = uri[53:61]
            hmac_key = self.xor_bytes(xored_key)[:32]
        except Exception as exc:
            self.error(item, f"资源 {resource_name} 的 URI 解析失败: {exc}")
            if retry_mode:
                item["retry_pending_files"] = list(retry_lookup.values())
                self.summary["retry_requested_files"] += len(retry_lookup)
                self.summary["retry_remaining_files"] += len(retry_lookup)
            item["status"] = "failed"
            self.resource_reports.append(item)
            return item

        temp_dir = os.path.join("Temp", res_name)
        unpacked_dir = os.path.join("Unpacked", res_name)
        file_jobs = []

        files = res.get("files") or {}
        stream_files = res.get("streamFiles") or {}
        available_retry_names = set()

        def classify_retry_file(file_name, regular_file):
            normalized = str(file_name).replace("\\", "/").casefold()
            if retry_mode:
                available_retry_names.add(normalized)
            requested = bool(retry_mode and normalized in retry_lookup)
            decrypt_context = bool(
                retry_mode
                and self.include_decrypt_prerequisites
                and self.retry_resource_is_fxap.get(resource_name) is not False
                and regular_file
                and (normalized.endswith(".rpf") or normalized == ".fxap")
            )
            prerequisite = bool(decrypt_context and not requested)
            return requested, prerequisite, decrypt_context

        for fname, file_data in files.items():
            retry_requested, retry_prerequisite, decrypt_context = classify_retry_file(fname, True)
            if retry_mode and not retry_requested and not retry_prerequisite:
                continue
            if retry_prerequisite:
                item["retry_prerequisite_files"].append(fname)
            hsh = get_file_hash(file_data)
            if not hsh:
                detail = {"file": fname, "attempts": 0, "status_code": None, "error": "文件缺少 hash，无法下载"}
                item["failed_downloads"].append(detail)
                item["failed_files"] += 1
                if retry_requested:
                    self.summary["retry_remaining_files"] += 1
                if decrypt_context:
                    item["retry_prerequisite_failed"] = True
                self.summary["failed_downloads"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"[下载最终失败] {resource_name}/{fname}：文件缺少 hash，无法下载。")
                continue
            base_url = (res.get("fileServer") or self.base_url + "/files").rstrip("/")
            url = f"{base_url}/{quote(res['name'], safe='')}/{encode_file_path(fname)}?hash={quote(str(hsh), safe='')}"
            rpf_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
            out_path = os.path.join(temp_dir if fname.endswith(".rpf") else unpacked_dir, fname)
            file_jobs.append((fname, url, rpf_key, iv, out_path, retry_requested, retry_prerequisite, decrypt_context))

        for fname, body in stream_files.items():
            retry_requested, retry_prerequisite, decrypt_context = classify_retry_file(fname, False)
            if retry_mode and not retry_requested:
                continue
            hsh = get_file_hash(body)
            if not hsh:
                detail = {"file": fname, "attempts": 0, "status_code": None, "error": "stream 文件缺少 hash，无法下载"}
                item["failed_downloads"].append(detail)
                item["failed_files"] += 1
                if retry_requested:
                    self.summary["retry_remaining_files"] += 1
                self.summary["failed_downloads"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"[下载最终失败] {resource_name}/{fname}：stream 文件缺少 hash，无法下载。")
                continue
            base_url = (res.get("fileServer") or self.base_url + "/files").rstrip("/")
            url = f"{base_url}/{quote(res['name'], safe='')}/{encode_file_path(fname)}?hash={quote(str(hsh), safe='')}"
            s_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
            out_path = os.path.join(unpacked_dir, "stream", fname)
            file_jobs.append((fname, url, s_key, iv, out_path, retry_requested, False, False))

        if retry_mode:
            missing_from_server = [
                original_name
                for normalized, original_name in retry_lookup.items()
                if normalized not in available_retry_names
            ]
            for fname in missing_from_server:
                detail = {
                    "file": fname,
                    "attempts": 0,
                    "status_code": None,
                    "error": "当前服务器配置中已不存在该文件",
                }
                item["failed_downloads"].append(detail)
                item["failed_files"] += 1
                self.summary["retry_remaining_files"] += 1
                self.summary["failed_downloads"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"[补充下载失败] {resource_name}/{fname}：当前服务器配置中已不存在该文件。")
            item["files_total"] = len(retry_lookup) + len(item["retry_prerequisite_files"])
            self.summary["retry_requested_files"] += len(retry_lookup)
            self.summary["retry_prerequisite_files"] += len(item["retry_prerequisite_files"])
            print(
                f"[补充下载] {resource_name}：失败文件 {len(retry_lookup)} 个，"
                f"解密前置文件 {len(item['retry_prerequisite_files'])} 个。"
            )
        else:
            item["files_total"] = len(files) + len(stream_files)
        print(f"[Dump] ({index}/{total}) 正在下载资源: {resource_name}，文件 {len(file_jobs)} 个。")
        rpf_files = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            future_map = {
                exe.submit(self.download_and_decrypt, url, key, iv_value, out_path, fname, resource_name): (
                    fname,
                    out_path,
                    retry_requested,
                    retry_prerequisite,
                    decrypt_context,
                )
                for fname, url, key, iv_value, out_path, retry_requested, retry_prerequisite, decrypt_context in file_jobs
            }
            for future in as_completed(future_map):
                fname, out_path, retry_requested, retry_prerequisite, decrypt_context = future_map[future]
                completed += 1
                try:
                    result = future.result()
                except DiskSpaceError:
                    for pending in future_map:
                        pending.cancel()
                    raise
                except Exception as exc:
                    result = {
                        "path": None,
                        "file": fname,
                        "attempts": 1,
                        "retries": 0,
                        "status_code": None,
                        "failure_stage": "process",
                        "error": str(exc),
                    }

                retries = int(result.get("retries", 0) or 0)
                if retries > 0:
                    item["download_retried_files"] += 1
                    item["download_retry_attempts"] += retries
                    self.summary["download_retried_files"] += 1
                    self.summary["download_retry_attempts"] += retries

                if result.get("path"):
                    item["downloaded_files"] += 1
                    self.summary["downloaded_files"] += 1
                    if retry_requested:
                        item["retry_recovered_files"].append(fname)
                        self.summary["retry_recovered_files"] += 1
                    if retries > 0:
                        item["download_retry_recovered"] += 1
                        self.summary["download_retry_recovered"] += 1
                        print(f"[下载重试成功] {resource_name}/{fname}，共尝试 {result.get('attempts')} 次。")
                    else:
                        print(f"[下载完成] {fname}")
                    if fname.endswith(".rpf"):
                        rpf_files.append((result["path"], fname, retry_requested, retry_prerequisite, decrypt_context))
                else:
                    item["failed_files"] += 1
                    self.summary["failed_files"] += 1
                    if retry_requested:
                        self.summary["retry_remaining_files"] += 1
                    if decrypt_context:
                        item["retry_prerequisite_failed"] = True
                    if result.get("failure_stage") == "download":
                        detail = {
                            "file": fname,
                            "attempts": int(result.get("attempts", 0) or 0),
                            "status_code": result.get("status_code"),
                            "error": result.get("error") or "未知下载错误",
                        }
                        item["failed_downloads"].append(detail)
                        self.summary["failed_downloads"] += 1
                        self.warn(
                            item,
                            f"[下载最终失败] {resource_name}/{fname}：共尝试 {detail['attempts']} 次；"
                            f"{detail['error']}。",
                        )
                    else:
                        self.warn(item, f"{fname} 处理失败: {result.get('error') or '未知错误'}")

                base = 28
                span = 34
                resource_ratio = ((index - 1) + (completed / max(1, len(file_jobs)))) / max(1, total)
                emit_progress(base + int(span * resource_ratio), "dump", f"正在 Dump {resource_name}: {completed}/{len(file_jobs)}")

        for rpf_path, rpf_name, retry_requested, retry_prerequisite, decrypt_context in rpf_files:
            if os.path.exists(rpf_path):
                unpacked = self.unpack_rpf(rpf_path, unpacked_dir, item)
                if retry_mode and self.include_decrypt_prerequisites and not unpacked:
                    item["retry_prerequisite_failed"] = True
            else:
                self.warn(item, f"RPF 文件不存在，已跳过: {rpf_path}")
                if retry_mode and self.include_decrypt_prerequisites:
                    item["retry_prerequisite_failed"] = True

        if item["failed_files"] == 0:
            item["status"] = "success"
        elif item["downloaded_files"] > 0:
            item["status"] = "partial"
        else:
            item["status"] = "failed"

        self.resource_reports.append(item)
        return item

    def print_resource_menu(self, resources):
        print(f"[资源菜单] 共 {len(resources)} 个资源")
        width = max(1, len(str(max(0, len(resources) - 1))))
        for index, resource in enumerate(resources):
            print(f"  {index:>{width}}  {resource.get('name', '')}")

    def print_resource_selection(self, selected):
        print(f"[资源选择] 已选 {len(selected)} 个资源:")
        for resource in selected[:200]:
            print(f"  - {resource.get('name', '')}")
        if len(selected) > 200:
            print(f"  ... 另有 {len(selected) - 200} 个资源")

    def select_resources(self, resources, choice):
        if isinstance(choice, (list, tuple, set)):
            selected, unmatched = resolve_resource_selection(resources, choice)
            if unmatched:
                if self.retry_files_by_resource is None:
                    detail = ", ".join(unmatched[:20])
                    raise RuntimeError(f"Confirmed resources are no longer available: {detail}")
                self.unmatched_retry_resources = list(unmatched)
            self.print_resource_selection(selected)
            return selected

        choice = (choice or "").strip()
        if choice:
            selected, unmatched = resolve_resource_selection(resources, choice)
            for token in unmatched:
                print_warning(f"Resource selector matched nothing and was ignored: {token}")
            self.print_resource_selection(selected)
            return selected

        self.print_resource_menu(resources)
        while True:
            expression = input(
                "请输入资源序号、精确名称或通配符（如 esx_*,*_cars），"
                "多个条件用逗号分隔；all 全选，q 取消: "
            ).strip()
            if expression.casefold() in ("q", "quit", "cancel"):
                raise ResourceSelectionCancelled("Resource selection cancelled by user")

            selected, unmatched = resolve_resource_selection(resources, expression)
            for token in unmatched:
                print_warning(f"未匹配到资源，已忽略: {token}")
            if not selected:
                print_warning("没有匹配到任何资源，请重新选择。")
                continue

            self.print_resource_selection(selected)
            confirmation = input(
                f"确认 Dump 以上 {len(selected)} 个资源？[y]确认 / [r]重选 / [q]取消: "
            ).strip().casefold()
            if confirmation in ("y", "yes", "是", "确认"):
                return selected
            if confirmation in ("q", "quit", "cancel", "取消"):
                raise ResourceSelectionCancelled("Resource selection cancelled by user")
            print("[资源选择] 已返回资源菜单，请重新选择。")

    def cleanup_resource_temp(self, resource_safe_name):
        for root_name in ("Temp", "Unpacked", "TempCompiled"):
            path = os.path.join(root_name, resource_safe_name)
            if not os.path.isdir(path):
                continue
            try:
                shutil.rmtree(path)
            except Exception as exc:
                print_warning(f"无法清理资源临时目录 {path}: {exc}")

    def run(self, resources_choice=None, on_resource_ready=None):
        resources = self.get_configuration()
        chosen = self.select_resources(resources, resources_choice)
        self.summary["resources_selected"] = len(chosen)

        if self.retry_files_by_resource is not None and self.unmatched_retry_resources:
            unavailable_names = self.unmatched_retry_resources
            self.summary["warnings"] += 1
            preview = ", ".join(unavailable_names[:20])
            suffix = f"，另有 {len(unavailable_names) - 20} 个" if len(unavailable_names) > 20 else ""
            print_warning(
                f"[补充下载] 当前服务器缺少 {len(unavailable_names)} 个旧报告资源，"
                f"已保留到下一轮，其他资源继续处理: {preview}{suffix}"
            )
            for resource_name in unavailable_names:
                retry_lookup = self.retry_files_by_resource.get(resource_name, {})
                requested_files = list(retry_lookup.values())
                self.summary["retry_requested_files"] += len(requested_files)
                self.summary["retry_remaining_files"] += len(requested_files)
                self.resource_reports.append({
                    "name": resource_name,
                    "safe_name": safe_name(resource_name),
                    "status": "unavailable",
                    "files_total": len(requested_files),
                    "downloaded_files": 0,
                    "download_retried_files": 0,
                    "download_retry_attempts": 0,
                    "download_retry_recovered": 0,
                    "failed_downloads": [],
                    "retry_mode": True,
                    "retry_requested_files": requested_files,
                    "retry_recovered_files": [],
                    "retry_pending_files": requested_files,
                    "retry_prerequisite_files": [],
                    "retry_prerequisite_failed": False,
                    "failed_files": 0,
                    "rpf_unpacked": 0,
                    "warnings": ["当前服务器资源清单中不存在该资源，已保留到下一轮补充。"],
                    "errors": [],
                })

        if not chosen:
            if self.retry_files_by_resource is not None:
                return self.resource_reports
            raise RuntimeError("No resources matched the requested selection")

        print(f"[Dump] 将处理 {len(chosen)} 个资源，并在每个资源完成后立即执行所选处理和释放临时文件。")
        for idx, res in enumerate(chosen, start=1):
            resource_name = res.get("name", f"resource_{idx}")
            resource_safe_name = safe_name(resource_name)
            try:
                item = self.fetch_resource(res, idx, len(chosen))
                unpacked_dir = os.path.join("Unpacked", resource_safe_name)
                if on_resource_ready and os.path.isdir(unpacked_dir):
                    on_resource_ready(unpacked_dir, resource_safe_name, item)
            finally:
                if not self.keep_temp:
                    self.cleanup_resource_temp(resource_safe_name)
        return self.resource_reports


class FiveMDecryptor:
    def __init__(self, output_dir="Output", java_executable="", work_guard=None, output_guard=None, require_java=True):
        self.DefaultKey = bytes([
            0xB3, 0xCB, 0x2E, 0x04, 0x87, 0x94, 0xD6, 0x73,
            0x08, 0x23, 0xC4, 0x93, 0x7A, 0xBD, 0x18, 0xAD,
            0x6B, 0xE6, 0xDC, 0xB3, 0x91, 0x43, 0x0D, 0x28,
            0xF9, 0x40, 0x9D, 0x48, 0x37, 0xB9, 0x38, 0xFB,
        ])
        self.HeaderToVerify = b"FXAP"
        self.AesKey = bytes([
            0x7A, 0xBA, 0x8D, 0x53, 0x25, 0x5B, 0x0E, 0xFD,
            0x16, 0xBD, 0x35, 0x22, 0xA0, 0xB9, 0x26, 0xA5,
            0x61, 0x83, 0x2E, 0xEC, 0xA2, 0x4B, 0xFD, 0x56,
            0x9E, 0xC0, 0x1D, 0x8F, 0x38, 0x40, 0x54, 0x6D,
        ])
        self.LuaHeader = bytes.fromhex("1b4c7561540019930d0a1a0a0408087856")
        self.OutputDir = str(output_dir)
        self.WorkGuard = work_guard
        self.OutputGuard = output_guard
        self.RequireJava = bool(require_java)
        self.JavaExecutable = os.path.abspath(java_executable) if java_executable else ""
        if self.RequireJava and (not self.JavaExecutable or not os.path.isfile(self.JavaExecutable)):
            raise RuntimeError("Java 环境未就绪，无法运行 unluac54.jar。")
        self.UnluacJar = str((SCRIPT_DIR / "Tools" / "Decompile" / "unluac54.jar").resolve())
        if self.RequireJava and not os.path.isfile(self.UnluacJar):
            raise RuntimeError(f"缺少 Lua 5.4 反编译器: {self.UnluacJar}")
        self.TempDir = "TempCompiled"
        self.KeymasterUrl = "https://keymaster.fivem.net/api/validate"
        self.summary = {
            "resources_total": 0,
            "resources_decrypted": 0,
            "resources_copied": 0,
            "resources_raw_preserved": 0,
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 0,
            "warnings": 0,
            "errors": 0,
        }
        self.resource_reports = []
        self._cloud_key_cache = {}
        self._cloud_request_lock = threading.Lock()
        self._cloud_next_request_at = 0.0

    def warn(self, item, message):
        self.summary["warnings"] += 1
        if item is not None:
            item["warnings"].append(message)
        print_warning(message)

    def error(self, item, message):
        self.summary["errors"] += 1
        if item is not None:
            item["errors"].append(message)
        print_error(message)

    def file_to_bytes(self, fp):
        with open(fp, "rb") as f:
            return f.read()

    def scan_for_id(self, buf: bytes):
        return int(buf[74:78].hex(), 16)

    def verify_encrypted(self, path):
        buf = self.file_to_bytes(path)
        return buf[:4] == self.HeaderToVerify

    def decrypt_file(self, path, key: bytes):
        buf = self.file_to_bytes(path)
        if buf[:4] != self.HeaderToVerify:
            return None
        iv = buf[74:86]
        enc = buf[86:]
        return self._chacha_decrypt(enc, key, iv)

    def decrypt_buffer(self, hexdata: bytes, key: bytes, bufferPtr=None, ivPtr=None):
        if not hexdata or not key:
            return None
        if bufferPtr is not None and ivPtr is not None:
            iv = hexdata[ivPtr : ivPtr + 12]
            enc = hexdata[bufferPtr:]
            return self._try_chacha_decrypt(enc, key, iv)

        if len(hexdata) >= 18:
            try:
                name_length = int.from_bytes(hexdata[4:6], "little")
                iv_start = 6 + name_length
                payload_start = iv_start + 12
                if payload_start <= len(hexdata):
                    derived = self._try_chacha_decrypt(hexdata[payload_start:], key, hexdata[iv_start:payload_start])
                    if derived is not None:
                        return derived
            except Exception:
                pass

        return self._try_chacha_decrypt(hexdata[92:], key, hexdata[80:92])

    def _try_chacha_decrypt(self, enc: bytes, key: bytes, iv: bytes):
        if not key or len(key) != 32 or not enc or len(iv) not in (8, 12):
            return None
        try:
            return self._chacha_decrypt(enc, key, iv)
        except Exception:
            return None

    def _chacha_decrypt(self, enc: bytes, key: bytes, iv: bytes):
        try:
            cipher = ChaCha20.new(key=key, nonce=iv)
            return cipher.decrypt(enc)
        except Exception:
            try:
                cipher = ChaCha20.new(key=key, nonce=iv[:8])
                return cipher.decrypt(enc)
            except Exception as exc:
                raise RuntimeError(f"ChaCha20 decrypt failed: {exc}") from exc

    def is_rsc_header(self, buf: bytes):
        return bool(buf and len(buf) >= 4 and buf[:4] in RSC_HEADERS)

    def is_stream_file(self, file_name: str):
        return Path(file_name).suffix.lower() in STREAM_EXTENSIONS

    def validate_decryption(self, buf: bytes):
        return bool(buf and (buf.startswith(b"\x1bLua") or self.is_rsc_header(buf)))

    def find_filename_end(self, buf: bytes):
        lower_exts = [ext.encode("ascii") for ext in STREAM_EXTENSIONS]
        lower_buf = buf.lower()
        limit = max(0, len(buf) - 20)
        for index in range(limit):
            window = lower_buf[index : index + 32]
            for ext in lower_exts:
                pos = window.find(ext)
                if pos != -1:
                    return index + pos + len(ext)
        return -1

    def decrypt_stream_buffer(self, encrypted_data: bytes, key: bytes):
        if not encrypted_data or len(encrypted_data) < 100 or not key:
            return None

        filename_end = self.find_filename_end(encrypted_data)
        if filename_end > 0:
            for offset in (0, 1, 2, 4, 8):
                iv_start = filename_end + offset
                if iv_start + 12 >= len(encrypted_data):
                    continue
                result = self._try_chacha_decrypt(encrypted_data[iv_start + 12 :], key, encrypted_data[iv_start : iv_start + 12])
                if self.is_rsc_header(result):
                    return result

        for iv_start in range(40, 121):
            if iv_start + 12 >= len(encrypted_data):
                continue
            result = self._try_chacha_decrypt(encrypted_data[iv_start + 12 :], key, encrypted_data[iv_start : iv_start + 12])
            if self.is_rsc_header(result):
                return result
        return None

    def add_key_candidate(self, candidates, seen, key):
        if not key or not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            return
        key = bytes(key)
        marker = key.hex()
        if marker not in seen:
            seen.add(marker)
            candidates.append(key)

    def calculate_client_key(self, grants_clk: bytes):
        if not grants_clk or len(grants_clk) < 16:
            return None
        iv = grants_clk[:16]
        enc = grants_clk[16:]
        cipher = AES.new(self.AesKey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc)
        try:
            return unpad(decrypted, AES.block_size)
        except ValueError:
            return decrypted

    def _wait_for_cloud_request_slot(self):
        now = time.monotonic()
        wait_seconds = max(0.0, getattr(self, "_cloud_next_request_at", 0.0) - now)
        if wait_seconds:
            time.sleep(wait_seconds)
        self._cloud_next_request_at = time.monotonic() + GRANTS_CLK_MIN_INTERVAL_SECONDS

    def _cloud_retry_delay(self, response, attempt):
        if response is not None and response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "")
            try:
                return min(300.0, max(0.0, float(retry_after)))
            except (TypeError, ValueError):
                return 60.0
        return min(8.0, 2.0 ** attempt)

    def derive_cloud_client_key(self, grants_clk: bytes, resource_id, item=None):
        if not grants_clk or len(grants_clk) != 0x30 or resource_id is None:
            return None

        if not hasattr(self, "_cloud_key_cache"):
            self._cloud_key_cache = {}
        if not hasattr(self, "_cloud_request_lock"):
            self._cloud_request_lock = threading.Lock()
        cache_key = (str(resource_id), grants_clk.hex())
        if cache_key in self._cloud_key_cache:
            return self._cloud_key_cache[cache_key]

        with self._cloud_request_lock:
            if cache_key in self._cloud_key_cache:
                return self._cloud_key_cache[cache_key]

            last_error = ""
            for attempt in range(GRANTS_CLK_MAX_ATTEMPTS):
                self._wait_for_cloud_request_slot()
                response = None
                try:
                    response = requests.post(
                        GRANTS_CLK_DERIVE_URL,
                        json={"resourceId": str(resource_id), "grants_clk": grants_clk.hex()},
                        headers={"Content-Type": "application/json", "User-Agent": "CK-DumpTool/1"},
                        timeout=15,
                    )
                except requests.RequestException as exc:
                    last_error = str(exc)
                else:
                    if response.status_code == 200:
                        try:
                            key_hex = (response.json() or {}).get("key", "")
                        except ValueError as exc:
                            last_error = f"invalid JSON response: {exc}"
                        else:
                            if re.fullmatch(r"[0-9a-fA-F]{64}", str(key_hex)):
                                key = bytes.fromhex(key_hex)
                                self._cloud_key_cache[cache_key] = key
                                return key
                            last_error = "invalid key response"
                    elif response.status_code == 429 or response.status_code in (408, 425) or response.status_code >= 500:
                        last_error = f"HTTP {response.status_code}"
                    else:
                        self.warn(item, f"Cloud grants_clk derive failed for resource {resource_id}: HTTP {response.status_code}")
                        self._cloud_key_cache[cache_key] = None
                        return None

                if attempt + 1 < GRANTS_CLK_MAX_ATTEMPTS:
                    delay = self._cloud_retry_delay(response, attempt)
                    print(
                        f"[FXAP] Cloud grants_clk derive retry for resource {resource_id} "
                        f"in {delay:g}s ({last_error})",
                        flush=True,
                    )
                    if delay:
                        time.sleep(delay)

            self.warn(item, f"Cloud grants_clk derive unavailable for resource {resource_id}: {last_error or 'request failed'}")
            return None

    def calculate_client_key_candidates(self, grants_clk: bytes, resource_id=None, item=None):
        candidates = []
        seen = set()
        try:
            self.add_key_candidate(candidates, seen, self.calculate_client_key(grants_clk))
        except Exception as exc:
            self.warn(item, f"AES grants_clk fallback failed for resource {resource_id}: {exc}")
        if grants_clk and len(grants_clk) >= 48:
            self.add_key_candidate(candidates, seen, grants_clk[16:48])
        return candidates

    def find_encrypted_sample_file(self, files, resource_path):
        for relative in files:
            if os.path.basename(relative).lower() == ".fxap":
                continue
            full_path = os.path.join(resource_path, relative)
            try:
                if self.verify_encrypted(full_path):
                    return full_path
            except Exception:
                continue
        return None

    def find_working_key_pair(self, fxap_layer, decrypt_key, alternative_keys):
        if decrypt_key:
            result = self.decrypt_buffer(fxap_layer, decrypt_key)
            if self.validate_decryption(result):
                return {"matched": True, "alternative_key": None}
        for alternative_key in alternative_keys:
            result = self.decrypt_buffer(fxap_layer, alternative_key)
            if self.validate_decryption(result):
                return {"matched": True, "alternative_key": alternative_key}
        return {"matched": False, "alternative_key": None}

    def build_grant_key_states(self, grants_data, resource_id, decrypt_key, grants_clk, item=None):
        states = [{
            "resource_id": str(resource_id),
            "decrypt_key": decrypt_key,
            "grants_clk": grants_clk,
            "local_candidates": self.calculate_client_key_candidates(grants_clk, resource_id, item),
        }]
        seen_ids = {str(resource_id)}
        grants_clk_data = grants_data.get("grants_clk") or {}

        for candidate_id, key_hex in (grants_data.get("grants") or {}).items():
            candidate_id = str(candidate_id)
            if candidate_id in seen_ids:
                continue
            seen_ids.add(candidate_id)
            try:
                candidate_key = bytes.fromhex(key_hex)
            except Exception:
                continue

            candidate_clk = grants_clk
            local_candidates = []
            clk_hex = grants_clk_data.get(candidate_id)
            if clk_hex:
                try:
                    candidate_clk = bytes.fromhex(clk_hex)
                    local_candidates = self.calculate_client_key_candidates(candidate_clk, candidate_id, item)
                except Exception:
                    local_candidates = []
            states.append({
                "resource_id": candidate_id,
                "decrypt_key": candidate_key,
                "grants_clk": candidate_clk,
                "local_candidates": local_candidates,
            })
        return states

    def resolve_working_keys(self, resource_path, files, grants_data, resource_id, decrypt_key, grants_clk, item=None):
        states = self.build_grant_key_states(
            grants_data,
            resource_id,
            decrypt_key,
            grants_clk,
            item,
        )
        primary = states[0]
        sample_path = self.find_encrypted_sample_file(files, resource_path)
        if not sample_path:
            return {
                "resource_id": primary["resource_id"],
                "decrypt_key": primary["decrypt_key"],
                "grants_clk": primary["grants_clk"],
                "alternative_key": primary["local_candidates"][0] if primary["local_candidates"] else None,
            }

        fxap_layer = self.decrypt_file(sample_path, self.DefaultKey)
        if not fxap_layer:
            return {
                "resource_id": primary["resource_id"],
                "decrypt_key": primary["decrypt_key"],
                "grants_clk": primary["grants_clk"],
                "alternative_key": primary["local_candidates"][0] if primary["local_candidates"] else None,
            }

        for state in states:
            match = self.find_working_key_pair(
                fxap_layer,
                state["decrypt_key"],
                state["local_candidates"],
            )
            if not match["matched"]:
                continue
            if state["resource_id"] != str(resource_id):
                self.warn(item, f"Resource ID switched from {resource_id} to {state['resource_id']} after key validation")
            return {
                "resource_id": state["resource_id"],
                "decrypt_key": state["decrypt_key"],
                "grants_clk": state["grants_clk"],
                "alternative_key": match["alternative_key"] or (
                    state["local_candidates"][0] if state["local_candidates"] else None
                ),
            }

        for state in states:
            cloud_key = self.derive_cloud_client_key(
                state["grants_clk"],
                state["resource_id"],
                item,
            )
            if not cloud_key:
                continue
            match = self.find_working_key_pair(fxap_layer, None, [cloud_key])
            if not match["matched"]:
                continue
            if state["resource_id"] != str(resource_id):
                self.warn(item, f"Resource ID switched from {resource_id} to {state['resource_id']} after cloud key validation")
            return {
                "resource_id": state["resource_id"],
                "decrypt_key": state["decrypt_key"],
                "grants_clk": state["grants_clk"],
                "alternative_key": cloud_key,
            }

        return {
            "resource_id": primary["resource_id"],
            "decrypt_key": primary["decrypt_key"],
            "grants_clk": primary["grants_clk"],
            "alternative_key": primary["local_candidates"][0] if primary["local_candidates"] else None,
        }

    def get_cloud_fallback_key(self, resource_id, grants_clk, existing_keys, item=None):
        cloud_key = self.derive_cloud_client_key(grants_clk, resource_id, item)
        if not cloud_key:
            return None
        for key in existing_keys:
            if key and bytes(key) == cloud_key:
                return None
        return cloud_key

    def write_binary_output(self, output_path, data: bytes):
        if self.OutputGuard:
            self.OutputGuard.check(required_bytes=len(data))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as out:
            out.write(data)

    def process_stream_file(self, decrypted_file, output_path, decrypt_key, alternative_key):
        keys = []
        seen = set()
        self.add_key_candidate(keys, seen, decrypt_key)
        self.add_key_candidate(keys, seen, alternative_key)
        for key in keys:
            result = self.decrypt_buffer(decrypted_file, key)
            if not self.is_rsc_header(result):
                result = self.decrypt_stream_buffer(decrypted_file, key)
            if self.is_rsc_header(result):
                self.write_binary_output(output_path, result)
                return True
        return False

    def process_lua_file(self, decrypted_buffer: bytes, output_path: str, resource_name: str, file_rel: str):
        tmp_path = os.path.join(self.TempDir, f"{resource_name}/{file_rel}c")
        if self.WorkGuard:
            self.WorkGuard.check(required_bytes=len(decrypted_buffer))
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        with open(tmp_path, "wb") as f:
            f.write(decrypted_buffer)

        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        bytecode_path = str(Path(output_path).with_suffix(".luac"))
        name_only = os.path.splitext(os.path.basename(output_path))[0]
        error_path = os.path.join(output_dir, f"error_{name_only}_unluac.txt")

        def save_failure(status, detail):
            full_detail = detail or "unluac 未返回错误详情"
            if self.OutputGuard:
                self.OutputGuard.check(required_bytes=len(decrypted_buffer) + len(full_detail.encode("utf-8", errors="ignore")))
            with open(bytecode_path, "wb") as out:
                out.write(decrypted_buffer)
            with open(error_path, "w", encoding="utf-8", errors="ignore") as error_file:
                error_file.write(full_detail)
            if os.path.isfile(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            message = f"Lua 反编译失败，字节码已保存为: {bytecode_path}，错误详情: {error_path}"
            print_warning(message)
            return {"status": status, "output": bytecode_path, "error": full_detail[:1600]}

        try:
            proc = subprocess.run(
                [self.JavaExecutable, "-jar", self.UnluacJar, tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "unluac 未返回错误详情").strip()
                return save_failure("decompile_error", detail)

            source = proc.stdout or ""
            if not source.strip():
                return save_failure("decompile_error", "unluac 返回成功，但没有生成 Lua 源码。")

            if self.OutputGuard:
                self.OutputGuard.check(required_bytes=len(source.encode("utf-8", errors="ignore")))
            with open(output_path, "w", encoding="utf-8", errors="ignore") as out:
                out.write(source)
            for stale_path in (bytecode_path, error_path):
                if os.path.isfile(stale_path):
                    try:
                        os.remove(stale_path)
                    except OSError:
                        pass
            return {"status": "decompiled", "output": output_path, "error": ""}
        except DiskSpaceError:
            raise
        except Exception as exc:
            return save_failure("java_error", f"unluac54.jar 执行失败: {exc}")

    def get_all_files(self, dirpath):
        results = []
        for root, _, files in os.walk(dirpath):
            for f in files:
                results.append(os.path.join(root, f))
        return results

    def collect_lua_decryption_candidates(self, decrypted_file, key_candidates):
        candidates = []
        candidate_errors = []
        for key_label, key in key_candidates:
            try:
                candidates.append((f"standard offset/{key_label}", self.decrypt_buffer(decrypted_file, key)))
            except Exception as exc:
                candidate_errors.append(f"standard offset/{key_label}: {exc}")
            try:
                candidates.append((
                    f"legacy offset/{key_label}",
                    self.decrypt_buffer(decrypted_file, key, bufferPtr=90, ivPtr=78),
                ))
            except Exception as exc:
                candidate_errors.append(f"legacy offset/{key_label}: {exc}")

        for key_label, key in key_candidates:
            for buffer_ptr in range(50, 151):
                for iv_ptr in range(38, 139):
                    if iv_ptr + 12 > buffer_ptr:
                        continue
                    candidate = self.decrypt_buffer(decrypted_file, key, bufferPtr=buffer_ptr, ivPtr=iv_ptr)
                    if candidate and candidate.startswith(self.LuaHeader):
                        candidates.append((f"scan {buffer_ptr}/{iv_ptr}/{key_label}", candidate))
                        break
                else:
                    continue
                break
        return candidates, candidate_errors

    def decrypt_resource_file(self, resource_path, relative_file, resource_id, decrypt_key, resource_name, grants_clk, alternative_key, item):
        try:
            full_path = os.path.join(resource_path, relative_file)
            output_path = os.path.join(self.OutputDir, resource_name, relative_file)

            if not os.path.exists(full_path):
                return {"status": "missing", "file": relative_file, "error": "file does not exist"}

            if not self.verify_encrypted(full_path):
                if self.OutputGuard:
                    self.OutputGuard.check(required_bytes=os.path.getsize(full_path))
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(full_path, "rb") as inf, open(output_path, "wb") as outf:
                    outf.write(inf.read())
                return {"status": "copied", "file": relative_file, "output": output_path}

            decrypted_file = self.decrypt_file(full_path, self.DefaultKey)
            if not decrypted_file:
                return {"status": "failed", "file": relative_file, "error": "initial FXAP decrypt failed"}
        except DiskSpaceError:
            raise
        except OSError as exc:
            if is_disk_full_error(exc) and self.OutputGuard:
                self.OutputGuard.raise_write_error(exc)
            return {"status": "failed", "file": relative_file, "error": f"processing error: {exc}"}
        except Exception as exc:
            return {"status": "failed", "file": relative_file, "error": f"processing error: {exc}"}

        try:
            if relative_file.lower().endswith(".lua"):
                output_dir = os.path.dirname(output_path)
                os.makedirs(output_dir, exist_ok=True)
                stale_paths = [
                    output_path,
                    str(Path(output_path).with_suffix(".luac")),
                    os.path.join(output_dir, f"error_{Path(output_path).stem}_unluac.txt"),
                ]
                for stale_path in stale_paths:
                    if os.path.isfile(stale_path):
                        try:
                            os.remove(stale_path)
                        except OSError:
                            pass

                key_candidates = [("grant key", decrypt_key)]
                if alternative_key and alternative_key != decrypt_key:
                    key_candidates.append(("local grants_clk key", alternative_key))

                candidates, candidate_errors = self.collect_lua_decryption_candidates(
                    decrypted_file,
                    key_candidates,
                )
                has_valid_candidate = any(
                    candidate and candidate.startswith(self.LuaHeader)
                    for _, candidate in candidates
                )
                if not has_valid_candidate:
                    cloud_key = self.get_cloud_fallback_key(
                        resource_id,
                        grants_clk,
                        [key for _, key in key_candidates],
                        item,
                    )
                    if cloud_key:
                        cloud_candidates, cloud_errors = self.collect_lua_decryption_candidates(
                            decrypted_file,
                            [("cloud grants_clk key", cloud_key)],
                        )
                        candidates.extend(cloud_candidates)
                        candidate_errors.extend(cloud_errors)
                decompile_failures = []
                last_result = None
                for method, candidate in candidates:
                    if not candidate or not candidate.startswith(self.LuaHeader):
                        continue
                    result = self.process_lua_file(candidate, output_path, resource_name, relative_file)
                    if result.get("status") == "decompiled":
                        return {
                            "status": "decrypted",
                            "file": relative_file,
                            "output": result.get("output") or output_path,
                            "lua": "decompiled",
                            "lua_method": method,
                        }
                    last_result = result
                    decompile_failures.append(f"{method}: {result.get('error') or result.get('status')}")

                if decompile_failures:
                    return {
                        "status": "failed",
                        "file": relative_file,
                        "output": (last_result or {}).get("output", ""),
                        "lua": (last_result or {}).get("status", "decompile_error"),
                        "error": "Lua bytecode decrypted, but unluac54.jar failed: " + " | ".join(decompile_failures),
                    }

                detail = "; ".join(candidate_errors)
                error = "all Lua decrypt candidates failed header validation"
                if detail:
                    error += ": " + detail
                return {"status": "failed", "file": relative_file, "error": error}

            if self.is_stream_file(relative_file):
                if self.process_stream_file(decrypted_file, output_path, decrypt_key, alternative_key):
                    return {"status": "decrypted", "file": relative_file, "output": output_path, "stream": "rsc"}
                cloud_key = self.get_cloud_fallback_key(
                    resource_id,
                    grants_clk,
                    [decrypt_key, alternative_key],
                    item,
                )
                if cloud_key and self.process_stream_file(decrypted_file, output_path, cloud_key, None):
                    return {"status": "decrypted", "file": relative_file, "output": output_path, "stream": "rsc-cloud"}
                return {"status": "failed", "file": relative_file, "error": "stream RSC decrypt failed"}

            decrypted_buffer = self.decrypt_buffer(decrypted_file, decrypt_key)
            if not decrypted_buffer and alternative_key:
                decrypted_buffer = self.decrypt_buffer(decrypted_file, alternative_key)
            if not decrypted_buffer:
                return {"status": "failed", "file": relative_file, "error": "resource data decrypt failed"}
            self.write_binary_output(output_path, decrypted_buffer)
            return {"status": "decrypted", "file": relative_file, "output": output_path}
        except DiskSpaceError:
            raise
        except OSError as exc:
            if is_disk_full_error(exc) and self.OutputGuard:
                self.OutputGuard.raise_write_error(exc)
            return {"status": "failed", "file": relative_file, "error": f"write failed: {exc}"}
        except Exception as exc:
            return {"status": "failed", "file": relative_file, "error": f"write failed: {exc}"}

    def validate_key_from_file(self, grants_path):
        with open(grants_path, "r", encoding="utf-8") as f:
            grants_token = f.read().strip()
        return {"success": True, "grants_token": grants_token}

    def copy_plain_resource(self, resource_path, resource_name, item, description="未加密资源"):
        copied = 0
        for file_full in self.get_all_files(resource_path):
            try:
                relative = os.path.relpath(file_full, resource_path).replace("\\", "/")
                output_path = os.path.join(self.OutputDir, resource_name, relative)
                if self.OutputGuard:
                    self.OutputGuard.check(required_bytes=os.path.getsize(file_full))
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(file_full, "rb") as inf, open(output_path, "wb") as outf:
                    outf.write(inf.read())
                copied += 1
            except DiskSpaceError:
                raise
            except OSError as exc:
                if is_disk_full_error(exc) and self.OutputGuard:
                    self.OutputGuard.raise_write_error(exc)
                item["failed_files"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"复制文件失败: {os.path.basename(file_full)}，{exc}")
            except Exception as exc:
                item["failed_files"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"复制文件失败: {os.path.basename(file_full)}，{exc}")
        item["copied_files"] += copied
        self.summary["copied_files"] += copied
        self.summary["resources_copied"] += 1
        print(f"[复制完成] {description}已复制: {resource_name}，文件 {copied} 个。")

    def preserve_raw_resource(self, resource_path, resource_name, source_complete=True, source_failed_files=0):
        self.summary["resources_total"] += 1
        if self.OutputGuard:
            self.OutputGuard.check(force=True)
        item = {
            "name": resource_name,
            "status": "pending",
            "is_fxap": os.path.isfile(os.path.join(resource_path, ".fxap")),
            "raw_preserved": True,
            "source_complete": bool(source_complete),
            "source_failed_files": int(source_failed_files or 0),
            "output_dir": str((Path(self.OutputDir) / resource_name).resolve()),
            "resource_id": "",
            "files_total": len(self.get_all_files(resource_path)),
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 0,
            "warnings": [],
            "errors": [],
        }

        try:
            self.copy_plain_resource(
                resource_path,
                resource_name,
                item,
                description="原始资源（未执行 FXAP 解密）",
            )
            if item["failed_files"] == 0 and item["source_complete"]:
                item["status"] = "raw_preserved"
                self.summary["resources_raw_preserved"] += 1
            elif item["copied_files"] > 0:
                item["status"] = "partial"
                if not item["source_complete"]:
                    self.warn(
                        item,
                        f"下载阶段有 {item['source_failed_files']} 个文件失败；已保留现有原始目录，但内容不完整。",
                    )
            else:
                item["status"] = "failed"
        except DiskSpaceError:
            raise
        except Exception as exc:
            self.error(item, f"原始资源保留失败: {resource_name}，{exc}")
            item["status"] = "failed"

        self.resource_reports.append(item)
        return item

    def record_retry_prerequisite_failure(self, resource_name, message, is_fxap=True):
        self.summary["resources_total"] += 1
        self.summary["errors"] += 1
        item = {
            "name": resource_name,
            "status": "failed",
            "is_fxap": bool(is_fxap),
            "raw_preserved": False,
            "output_dir": str((Path(self.OutputDir) / resource_name).resolve()),
            "resource_id": "",
            "files_total": 0,
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 1,
            "warnings": [],
            "errors": [str(message)],
        }
        self.summary["failed_files"] += 1
        self.resource_reports.append(item)
        print_error(message)
        return item

    def decrypt_resource(self, resource_path, resource_name, grants_token=None):
        self.summary["resources_total"] += 1
        if self.OutputGuard:
            self.OutputGuard.check(force=True)
        item = {
            "name": resource_name,
            "status": "pending",
            "is_fxap": False,
            "output_dir": str((Path(self.OutputDir) / resource_name).resolve()),
            "resource_id": "",
            "files_total": 0,
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 0,
            "warnings": [],
            "errors": [],
        }

        try:
            fxap_file = os.path.join(resource_path, ".fxap")
            if not os.path.exists(fxap_file):
                self.copy_plain_resource(resource_path, resource_name, item)
                item["status"] = "copied"
                self.resource_reports.append(item)
                return item

            item["is_fxap"] = True

            fxap_buffer = self.decrypt_file(fxap_file, self.DefaultKey)
            if not fxap_buffer:
                self.error(item, f".fxap 初始解密失败: {resource_name}")
                item["status"] = "failed"
                self.resource_reports.append(item)
                return item

            resource_id = self.scan_for_id(fxap_buffer)
            item["resource_id"] = str(resource_id)

            if grants_token is None:
                grants_path = os.path.join("Resources", "Grants.txt")
                if not os.path.exists(grants_path):
                    self.error(item, f"缺少 Resources/Grants.txt，无法解密资源: {resource_name}")
                    item["status"] = "failed"
                    self.resource_reports.append(item)
                    return item
                data = self.validate_key_from_file(grants_path)
            else:
                data = {"success": True, "grants_token": grants_token}

            if not data.get("success"):
                self.error(item, f"授权 token 验证失败: {resource_name}")
                item["status"] = "failed"
                self.resource_reports.append(item)
                return item

            try:
                payload_part = data["grants_token"].split(".")[1]
                payload_part += "=" * (-len(payload_part) % 4)
                payload = json.loads(base64.b64decode(payload_part).decode("utf-8"))
            except Exception as exc:
                self.error(item, f"解析 grants token 失败: {exc}")
                item["status"] = "failed"
                self.resource_reports.append(item)
                return item

            if str(resource_id) not in payload.get("grants", {}):
                self.warn(item, f"资源未授权，跳过: {resource_name} (ID {resource_id})")
                item["status"] = "unauthorized"
                self.resource_reports.append(item)
                return item

            grants_data = {
                "grants": payload.get("grants", {}),
                "grants_clk": payload.get("grants_clk", {}),
            }
            decrypt_key = bytes.fromhex(grants_data["grants"][str(resource_id)])
            grants_clk_hex = grants_data["grants_clk"].get(str(resource_id), "")
            if not grants_clk_hex:
                self.error(item, f"missing grants_clk for resource {resource_name} (ID {resource_id})")
                item["status"] = "failed"
                self.resource_reports.append(item)
                return item
            grants_clk = bytes.fromhex(grants_clk_hex)

            print(f"[FXAP] Resolving keys with cloud grants_clk API: {resource_name} (ID: {resource_id})")

            files = [f for f in self.get_all_files(resource_path) if not f.endswith(".fxap")]
            relative_files = [os.path.relpath(f, resource_path).replace("\\", "/") for f in files]
            item["files_total"] = len(files)

            key_state = self.resolve_working_keys(
                resource_path,
                relative_files,
                grants_data,
                str(resource_id),
                decrypt_key,
                grants_clk,
                item,
            )
            resolved_resource_id = key_state["resource_id"]
            item["resource_id"] = str(resolved_resource_id)
            decrypt_key = key_state["decrypt_key"]
            grants_clk = key_state["grants_clk"]
            alternative_key = key_state.get("alternative_key")

            tasks = []
            with ThreadPoolExecutor(max_workers=6) as exe:
                for relative in relative_files:
                    tasks.append(exe.submit(
                        self.decrypt_resource_file,
                        resource_path,
                        relative,
                        resolved_resource_id,
                        decrypt_key,
                        resource_name,
                        grants_clk,
                        alternative_key,
                        item,
                    ))

                for task in as_completed(tasks):
                    try:
                        result = task.result()
                    except DiskSpaceError:
                        for pending in tasks:
                            pending.cancel()
                        raise
                    except Exception as exc:
                        result = {"status": "failed", "file": "", "error": str(exc)}

                    if result["status"] == "decrypted":
                        item["decrypted_files"] += 1
                        self.summary["decrypted_files"] += 1
                    elif result["status"] == "copied":
                        item["copied_files"] += 1
                        self.summary["copied_files"] += 1
                    else:
                        item["failed_files"] += 1
                        self.summary["failed_files"] += 1
                        self.warn(item, f"{result.get('file') or resource_name} decrypt failed: {result.get('error') or 'unknown error'}")
            if item["failed_files"] == 0:
                item["status"] = "decrypted"
                self.summary["resources_decrypted"] += 1
            elif item["decrypted_files"] or item["copied_files"]:
                item["status"] = "partial"
            else:
                item["status"] = "failed"

            self.resource_reports.append(item)
            return item
        except DiskSpaceError:
            raise
        except Exception as exc:
            self.error(item, f"资源处理异常: {resource_name}，{exc}")
            item["status"] = "failed"
            self.resource_reports.append(item)
            return item

    def decrypt_all_resources(self):
        resources_root = "Unpacked"
        if not os.path.isdir(resources_root):
            print_warning("未找到 Unpacked/ 目录，跳过 FXAP 解密。请先完成 Dump 和 RPF 解包。")
            return self.resource_reports

        resource_dirs = []
        for entry in os.listdir(resources_root):
            full = os.path.join(resources_root, entry)
            if os.path.isdir(full):
                resource_dirs.append(full)

        if not resource_dirs:
            print_warning("Unpacked/ 中没有可解密资源。")
            return self.resource_reports

        for index, resource_dir in enumerate(resource_dirs, start=1):
            resource_name = os.path.basename(resource_dir)
            emit_progress(64 + int(24 * (index - 1) / max(1, len(resource_dirs))), "fxap", f"正在解密 FXAP: {resource_name}")
            self.decrypt_resource(resource_dir, resource_name)

        emit_progress(88, "fxap", "FXAP 解密阶段完成。")
        return self.resource_reports

    def start(self):
        print("[FXAP] 开始解密资源。")
        result = self.decrypt_all_resources()
        print("[FXAP] 解密流程结束。")
        return result


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="FiveM 服务器 Dump 与 FXAP 解密工具。",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="cfx.re 链接或 IP:端口，例如 https://cfx.re/join/xxxx 或 1.2.3.4:30120")
    parser.add_argument("--token-choice", choices=["1", "2"], default="1", help="1 自动扫描 FiveM token，2 使用手动 token")
    parser.add_argument("--token", default="", help="手动 token；token-choice=2 时使用，也可作为自动扫描失败后的备用 token")
    parser.add_argument("--resources", default=None, help="资源选择：支持 all、序号、精确名称和 *、? 通配符，多个条件用逗号分隔；非交互模式默认 all")
    parser.add_argument("--resources-file", default="", help="包含精确资源名数组的 JSON 文件")
    parser.add_argument("--retry-failed-report", default="", help="读取上一次 server-dump JSON 报告，只补充下载其中失败或待处理的文件并合并回原输出目录")
    parser.add_argument("--list-resources", action="store_true", help="仅获取并输出服务器资源清单，不执行 Dump")
    parser.add_argument("--output", default="Output", help="Dump 处理输出目录")
    parser.add_argument("--report", default="", help="报告路径。可传 report.json、report.md 或目录")
    parser.add_argument("--java", default="", help="Java 安装目录或 java.exe；最低 Java 8，推荐 Java 17")
    parser.add_argument("--temp-dir", default="", help="临时工作区的父目录；默认使用输出目录所在磁盘")
    parser.add_argument("--min-free-gb", type=float, default=DEFAULT_MIN_FREE_GB, help="输出与临时磁盘必须保留的最小空间（GB）")
    parser.add_argument("--non-interactive", action="store_true", help="非交互模式，缺少必要信息时直接失败")
    parser.add_argument("--keep-temp", action="store_true", help="保留本次运行的临时工作区；默认逐资源处理后清理")
    parser.add_argument("--no-fxap-decrypt", action="store_true", help="不执行 FXAP 解密，将下载、解包后的原始资源（含 .fxap）按完整目录复制到输出")
    parser.add_argument("--vertex-fix", action="store_true", help="FXAP 解密完成后，在原输出目录旁复制完整资源并对副本执行顶点修复")
    return parser.parse_args(argv)


def resolve_report_paths(report_arg, output_dir):
    if report_arg:
        report_path = Path(report_arg)
        if not report_path.is_absolute():
            report_path = Path.cwd() / report_path
        suffix = report_path.suffix.lower()
        if suffix == ".json":
            json_path = report_path
            markdown_path = report_path.with_suffix(".md")
        elif suffix == ".md":
            markdown_path = report_path
            json_path = report_path.with_suffix(".json")
        else:
            json_path = report_path / "report.json"
            markdown_path = report_path / "report.md"
    else:
        json_path = Path(output_dir) / "_server_dump_report.json"
        markdown_path = Path(output_dir) / "_server_dump_report.md"

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    return json_path, markdown_path


def build_markdown_report(report):
    summary = report.get("summary", {})
    scope = report.get("scope", {})
    java = report.get("java", {})
    storage = report.get("storage", {})
    lines = [
        "# 服务器 Dump 报告",
        "",
        f"- 状态: {report.get('status', '')}",
        f"- 目标: {report.get('target', '')}",
        f"- 服务器地址: {report.get('server_address', '')}",
        f"- 输出目录: {report.get('output', '')}",
        f"- 开始时间: {report.get('started_at', '')}",
        f"- 结束时间: {report.get('finished_at', '')}",
        f"- 耗时: {report.get('elapsed_seconds', 0)} 秒",
        "",
        "## 功能范围",
        "",
        f"- 服务器 Dump: {'包含' if scope.get('serverDump') else '不包含'}",
        f"- FXAP 解密: {'包含' if scope.get('fxapDecrypt') else '不包含'}",
        f"- 原始 FXAP 资源完整保留: {'包含' if scope.get('rawResourcePreservation') else '不包含'}",
        f"- 顶点修复: {'包含（可选）' if scope.get('vertexFix') else '不包含'}",
        f"- 模型修复: {'包含' if scope.get('modelRepair') else '不包含'}",
        "",
        "## 存储与临时目录",
        "",
        f"- 输出目录: {storage.get('output_dir', report.get('output', ''))}",
        f"- 临时工作区: {storage.get('temp_dir', '')}",
        f"- 临时策略: {'保留' if storage.get('temp_kept') else '逐资源解密后立即清理'}",
        f"- 最小保留空间: {storage.get('minimum_free_gb', DEFAULT_MIN_FREE_GB)} GB",
        f"- 启动时输出盘剩余: {storage.get('output_initial_free_gb', '')} GB",
        f"- 启动时临时盘剩余: {storage.get('temp_initial_free_gb', '')} GB",
        f"- 结束时输出盘剩余: {storage.get('output_final_free_gb', '')} GB",
        "",
        "## Java 环境",
        "",
        f"- 本次是否需要: {'是' if java.get('required', True) else '否'}",
        f"- 状态: {'已就绪' if java.get('ok') else ('未检测（本次不需要）' if not java.get('required', True) else '不可用')}",
        f"- 版本: {java.get('version', '')}",
        f"- 路径: {java.get('path', '')}",
        f"- 要求: 最低 Java {JAVA_MINIMUM_MAJOR}，推荐 Java {JAVA_RECOMMENDED_MAJOR}",
        "",
        "## 汇总",
        "",
        f"- 服务器资源总数: {summary.get('server_resources_total', 0)}",
        f"- 本次选择资源: {summary.get('server_resources_selected', 0)}",
        f"- Dump 下载成功文件: {summary.get('downloaded_files', 0)}",
        f"- 发生过重试的文件: {summary.get('download_retried_files', 0)}",
        f"- 下载额外重试次数: {summary.get('download_retry_attempts', 0)}",
        f"- 重试后下载成功: {summary.get('download_retry_recovered', 0)}",
        f"- 最终未下载成功: {summary.get('failed_downloads', 0)}",
        f"- RPF 解包成功: {summary.get('rpf_unpacked', 0)}",
        f"- FXAP 解密资源: {summary.get('resources_decrypted', 0)}",
        f"- 复制资源: {summary.get('resources_copied', 0)}",
        f"- 完整保留原始资源: {summary.get('resources_raw_preserved', 0)}",
        f"- 输出文件数: {summary.get('output_files', 0)}",
        f"- 失败文件数: {summary.get('failed_files', 0)}",
        f"- 警告: {summary.get('warnings', 0)}",
        f"- 错误: {summary.get('errors', 0)}",
        "",
        "## 补充失败下载",
        "",
        f"- 启用: {'是' if report.get('retry_failed', {}).get('enabled') else '否'}",
        f"- 来源报告: {report.get('retry_failed', {}).get('source_report', '')}",
        f"- 请求补充文件: {report.get('retry_failed', {}).get('requested_files', 0)}",
        f"- 本次下载成功: {report.get('retry_failed', {}).get('recovered_files', 0)}",
        f"- 仍需补充: {report.get('retry_failed', {}).get('remaining_files', 0)}",
        f"- 额外解密前置文件: {report.get('retry_failed', {}).get('prerequisite_files', 0)}",
        "",
        "## 顶点修复",
        "",
        f"- 启用: {'是' if report.get('vertex_fix', {}).get('enabled') else '否'}",
        f"- 状态: {report.get('vertex_fix', {}).get('status', 'disabled')}",
        f"- 原解密目录: {report.get('vertex_fix', {}).get('source_output', report.get('output', ''))}",
        f"- 修复副本目录: {report.get('vertex_fix', {}).get('output', '')}",
        f"- 符合条件的 FXAP 资源: {report.get('vertex_fix', {}).get('resources_eligible', 0)}",
        f"- 已复制完整资源: {report.get('vertex_fix', {}).get('resources_copied', 0)}",
        f"- 扫描文件: {report.get('vertex_fix', {}).get('scanned_files', 0)}",
        f"- 成功处理: {report.get('vertex_fix', {}).get('repaired_files', 0)}",
        f"- 失败文件: {report.get('vertex_fix', {}).get('failed_files', 0)}",
        f"- 风险提示: {report.get('vertex_fix', {}).get('disclaimer', VERTEX_FIX_DISCLAIMER)}",
        "",
        "## Dump 资源",
        "",
    ]

    dump_resources = report.get("dump_resources", [])
    if dump_resources:
        for item in dump_resources[:200]:
            lines.append(
                f"- [{item.get('status', '')}] {item.get('name', '')}: "
                f"下载 {item.get('downloaded_files', 0)}/{item.get('files_total', 0)}，"
                f"重试文件 {item.get('download_retried_files', 0)}，"
                f"最终未下载 {len(item.get('failed_downloads', []))}，"
                f"RPF 解包 {item.get('rpf_unpacked', 0)}"
            )
            if item.get("retry_mode"):
                lines.append(
                    f"  - 补充请求 {len(item.get('retry_requested_files', []))}，"
                    f"本次下载成功 {len(item.get('retry_recovered_files', []))}，"
                    f"待下次继续 {len(item.get('retry_pending_files', []))}，"
                    f"额外前置文件 {len(item.get('retry_prerequisite_files', []))}"
                )
            for warning in item.get("warnings", [])[:5]:
                lines.append(f"  - 警告: {warning}")
            for error in item.get("errors", [])[:5]:
                lines.append(f"  - 错误: {error}")
    else:
        lines.append("- 无")

    lines.extend(["", "## 最终未下载成功文件", ""])
    failed_download_count = 0
    for item in dump_resources:
        for failure in item.get("failed_downloads", []):
            failed_download_count += 1
            status_code = failure.get("status_code")
            status_text = f"HTTP {status_code}" if status_code is not None else "无 HTTP 状态码"
            lines.append(
                f"- {item.get('name', '')}/{failure.get('file', '')}: {status_text}，"
                f"尝试 {failure.get('attempts', 0)} 次，原因: {failure.get('error', '')}"
            )
    if failed_download_count == 0:
        lines.append("- 无")

    if report.get("retry_failed", {}).get("enabled"):
        lines.extend(["", "## 下一轮仍需补充", ""])
        remaining_by_resource = report.get("retry_failed", {}).get("remaining_by_resource", {}) or {}
        if remaining_by_resource:
            for resource_name, file_names in remaining_by_resource.items():
                for file_name in file_names:
                    lines.append(f"- {resource_name}/{file_name}")
        else:
            lines.append("- 无")

    lines.extend(["", "## FXAP 解密资源", ""])
    decrypt_resources = report.get("decrypt_resources", [])
    if decrypt_resources:
        for item in decrypt_resources[:200]:
            lines.append(
                f"- [{item.get('status', '')}] {item.get('name', '')}: "
                f"解密 {item.get('decrypted_files', 0)}，复制 {item.get('copied_files', 0)}，失败 {item.get('failed_files', 0)}"
            )
            if item.get("resource_id"):
                lines.append(f"  - Resource ID: {item.get('resource_id')}")
            for warning in item.get("warnings", [])[:5]:
                lines.append(f"  - 警告: {warning}")
            for error in item.get("errors", [])[:5]:
                lines.append(f"  - 错误: {error}")
    else:
        lines.append("- 无")

    lines.extend(["", "## 原始资源完整保留", ""])
    raw_resources = report.get("raw_resources", [])
    if raw_resources:
        for item in raw_resources[:200]:
            lines.append(
                f"- [{item.get('status', '')}] {item.get('name', '')}: "
                f"FXAP {'是' if item.get('is_fxap') else '否'}，"
                f"下载源 {'完整' if item.get('source_complete', True) else '不完整'}，"
                f"完整目录文件 {item.get('copied_files', 0)}/{item.get('files_total', 0)}，"
                f"失败 {item.get('failed_files', 0)}，输出 {item.get('output_dir', '')}"
            )
            for warning in item.get("warnings", [])[:5]:
                lines.append(f"  - 警告: {warning}")
            for error in item.get("errors", [])[:5]:
                lines.append(f"  - 错误: {error}")
    else:
        lines.append("- 无")

    if len(dump_resources) > 200 or len(decrypt_resources) > 200 or len(raw_resources) > 200:
        lines.extend(["", "仅显示前 200 个资源，完整明细请查看 JSON 报告。"])

    return "\n".join(lines) + "\n"


def write_reports(report, json_path, markdown_path):
    report["execution_report"] = {
        "json": str(json_path),
        "markdown": str(markdown_path),
    }
    json_text = json.dumps(report, ensure_ascii=False, indent=2)
    json_path.write_text(json_text, encoding="utf-8")
    markdown_path.write_text(build_markdown_report(report), encoding="utf-8")
    print("CK_REPORT " + json.dumps(report["execution_report"], ensure_ascii=False), flush=True)


def cleanup_temp(work_dir, keep_temp):
    work_dir = Path(work_dir).resolve()
    os.chdir(SCRIPT_DIR)
    if keep_temp:
        print(f"[清理] 已按参数保留本次临时工作区: {work_dir}")
        return

    if not work_dir.name.startswith("_ck_dump_temp_"):
        raise RuntimeError(f"拒绝清理非本工具临时目录: {work_dir}")

    emit_progress(96, "cleanup", "正在清理本次临时工作区。")
    if work_dir.is_dir():
        shutil.rmtree(work_dir)
        print(f"[清理] 已删除本次临时工作区: {work_dir}")


def choose_token(args):
    if args.token_choice == "2":
        token = (args.token or "").strip()
        if not token and not args.non_interactive:
            token = input("请输入自定义 token: ").strip()
        if not token:
            raise RuntimeError("已选择手动 token，但没有提供 token。")
        token = normalize_token(token)
        print(f"[Token] 使用自定义 token: {mask_token(token)}")
        return token

    emit_progress(5, "token", "正在扫描 FiveM 进程中的 token。")
    print("[Token] 正在自动扫描 FiveM 进程。")
    token = get_token()
    if not token and args.token:
        token = args.token.strip()
        print("[Token] 自动扫描失败，已使用命令行提供的备用 token。")
    if not token and not args.non_interactive:
        fallback = input("未找到 token，是否手动输入？(y/N): ").strip().lower()
        if fallback in ["y", "yes", "是"]:
            token = input("请输入 token: ").strip()
    if not token:
        raise RuntimeError("没有可用 token。请确认 FiveM 正在运行且已进入服务器，或使用 --token-choice 2 --token。")
    token = normalize_token(token)
    print(f"[Token] 已获取 token: {mask_token(token)}")
    return token


def run_resource_listing(args):
    os.chdir(SCRIPT_DIR)
    payload = {
        "schemaVersion": 1,
        "version": TOOL_VERSION,
        "command": "list-resources",
        "status": "error",
        "target": args.target or "",
        "server_address": "",
        "base_url": "",
        "resources": [],
        "error": "",
    }
    try:
        target = (args.target or "").strip()
        if not target and not args.non_interactive:
            target = input("Enter a cfx.re link or IP:port: ").strip()
        if not target:
            raise RuntimeError("Target address is required")
        payload["target"] = target

        token = choose_token(args)
        emit_progress(15, "resolve", "Resolving server address")
        endpoint = resolve_server_endpoint(target)
        payload["server_address"] = endpoint["address"]
        payload["base_url"] = endpoint["base_urls"][0]

        dumper = FiveMDumper(
            endpoint["base_urls"][0],
            token,
            max_workers=1,
            fallback_base_urls=endpoint["base_urls"][1:],
        )
        resources = dumper.get_configuration(save_grants=False)
        payload["base_url"] = dumper.base_url
        payload["resources"] = [
            {"index": index, "name": str(resource.get("name", ""))}
            for index, resource in enumerate(resources)
        ]
        payload["status"] = "success"
        emit_progress(100, "resource_list", f"Loaded {len(resources)} resources")
    except Exception as exc:
        payload["error"] = str(exc)
        print_error(payload["error"])

    serialized = json.dumps(payload, ensure_ascii=False)
    print("CK_RESOURCE_LIST " + serialized, flush=True)
    print(serialized, flush=True)
    return 0 if payload["status"] == "success" else 2


def run_tool(args):
    os.chdir(SCRIPT_DIR)
    start_time = time.time()
    started_at = now_iso()
    retry_plan = None
    retry_plan_error = ""
    if args.retry_failed_report:
        try:
            retry_plan = load_failed_download_retry_report(args.retry_failed_report)
            supplied_target = str(args.target or "").strip().rstrip("/")
            report_target = retry_plan["target"].strip().rstrip("/")
            if supplied_target and supplied_target.casefold() != report_target.casefold():
                raise RuntimeError("补充下载报告的目标服务器与命令行目标不一致。")
            args.target = retry_plan["target"]
            args.output = retry_plan["output"]
            args.resources = None
            args.resources_file = ""
            args.no_fxap_decrypt = bool(retry_plan["raw_mode"])
            args.vertex_fix = False
        except Exception as exc:
            retry_plan_error = str(exc)
    decrypt_enabled = not bool(args.no_fxap_decrypt)

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = SCRIPT_DIR / output_dir
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path, markdown_path = resolve_report_paths(args.report, output_dir)

    minimum_free_gb = max(1.0, float(args.min_free_gb or DEFAULT_MIN_FREE_GB))
    work_dir = create_work_dir(args.temp_dir, output_dir)
    output_guard = DiskSpaceGuard(output_dir, minimum_free_gb, "输出目录磁盘")
    work_guard = DiskSpaceGuard(work_dir, minimum_free_gb, "临时工作区磁盘")

    report = {
        "version": TOOL_VERSION,
        "command": "server-dump",
        "status": "running",
        "started_at": started_at,
        "finished_at": "",
        "elapsed_seconds": 0,
        "target": args.target or "",
        "server_address": "",
        "base_url": "",
        "output": str(output_dir),
        "token_choice": args.token_choice,
        "resources_requested": list(retry_plan["files_by_resource"].keys()) if retry_plan else (args.resources_file or args.resources or ("all" if args.non_interactive else "")),
        "java": {
            "ok": False,
            "required": decrypt_enabled,
            "requested": args.java or "",
            "path": "",
            "version": "",
            "major": None,
        },
        "storage": {
            "output_dir": str(output_dir),
            "temp_dir": str(work_dir),
            "temp_kept": bool(args.keep_temp),
            "minimum_free_gb": minimum_free_gb,
            "output_initial_free_gb": "",
            "temp_initial_free_gb": "",
            "output_final_free_gb": "",
        },
        "scope": {
            "serverDump": True,
            "fxapDecrypt": decrypt_enabled,
            "rawResourcePreservation": not decrypt_enabled,
            "vertexFix": bool(args.vertex_fix),
            "modelRepair": False,
        },
        "vertex_fix": {
            "enabled": bool(args.vertex_fix),
            "status": "pending" if args.vertex_fix else "disabled",
            "source_output": str(output_dir),
            "output": "",
            "resources_eligible": 0,
            "resources_copied": 0,
            "scanned_files": 0,
            "repaired_files": 0,
            "failed_files": 0,
            "exit_code": None,
            "warnings": [],
            "disclaimer": VERTEX_FIX_DISCLAIMER,
        },
        "summary": {},
        "dump_summary": {},
        "decrypt_summary": {},
        "dump_resources": [],
        "decrypt_resources": [],
        "raw_resources": [],
        "retry_failed": {
            "enabled": bool(args.retry_failed_report),
            "source_report": retry_plan["source_report"] if retry_plan else str(args.retry_failed_report or ""),
            "requested_files": int(retry_plan["requested_files"]) if retry_plan else 0,
            "requested_by_resource": retry_plan["files_by_resource"] if retry_plan else {},
            "recovered_files": 0,
            "remaining_files": 0,
            "remaining_by_resource": {},
            "prerequisite_files": 0,
        },
        "warnings": [],
        "errors": [],
    }

    exit_code = 0
    dumper = None
    decryptor = None

    def update_report_summaries():
        if dumper is not None:
            report["dump_summary"] = dumper.summary
            report["dump_resources"] = dumper.resource_reports
        if decryptor is not None:
            report["decrypt_summary"] = decryptor.summary
            if decrypt_enabled:
                report["decrypt_resources"] = decryptor.resource_reports
                report["raw_resources"] = []
            else:
                report["decrypt_resources"] = []
                report["raw_resources"] = decryptor.resource_reports

        dump_summary = report.get("dump_summary") or {}
        decrypt_summary = report.get("decrypt_summary") or {}
        failed_files = int(dump_summary.get("failed_files", 0)) + int(decrypt_summary.get("failed_files", 0))
        warnings = int(dump_summary.get("warnings", 0)) + int(decrypt_summary.get("warnings", 0)) + len(report["warnings"])
        errors = int(dump_summary.get("errors", 0)) + int(decrypt_summary.get("errors", 0)) + len(report["errors"])
        report["summary"] = {
            "server_resources_total": int(dump_summary.get("resources_total", 0)),
            "server_resources_selected": int(dump_summary.get("resources_selected", 0)),
            "downloaded_files": int(dump_summary.get("downloaded_files", 0)),
            "download_retried_files": int(dump_summary.get("download_retried_files", 0)),
            "download_retry_attempts": int(dump_summary.get("download_retry_attempts", 0)),
            "download_retry_recovered": int(dump_summary.get("download_retry_recovered", 0)),
            "failed_downloads": int(dump_summary.get("failed_downloads", 0)),
            "retry_requested_files": int(dump_summary.get("retry_requested_files", 0)),
            "retry_recovered_files": int(dump_summary.get("retry_recovered_files", 0)),
            "retry_remaining_files": int(dump_summary.get("retry_remaining_files", 0)),
            "retry_prerequisite_files": int(dump_summary.get("retry_prerequisite_files", 0)),
            "rpf_unpacked": int(dump_summary.get("rpf_unpacked", 0)),
            "resources_decrypted": int(decrypt_summary.get("resources_decrypted", 0)),
            "resources_copied": int(decrypt_summary.get("resources_copied", 0)),
            "resources_raw_preserved": int(decrypt_summary.get("resources_raw_preserved", 0)),
            "decrypted_files": int(decrypt_summary.get("decrypted_files", 0)),
            "copied_files": int(decrypt_summary.get("copied_files", 0)),
            "failed_files": failed_files,
            "warnings": warnings,
            "errors": errors,
            "output_files": count_files(output_dir),
            "vertex_fix_scanned_files": int((report.get("vertex_fix") or {}).get("scanned_files", 0)),
            "vertex_fix_repaired_files": int((report.get("vertex_fix") or {}).get("repaired_files", 0)),
            "vertex_fix_failed_files": int((report.get("vertex_fix") or {}).get("failed_files", 0)),
        }
        report["retry_failed"]["recovered_files"] = int(dump_summary.get("retry_recovered_files", 0))
        report["retry_failed"]["remaining_files"] = int(dump_summary.get("retry_remaining_files", 0))
        report["retry_failed"]["prerequisite_files"] = int(dump_summary.get("retry_prerequisite_files", 0))
        if retry_plan:
            items_by_name = {
                str(item.get("name") or ""): item
                for item in report.get("dump_resources", [])
                if isinstance(item, dict) and item.get("name")
            }
            remaining_by_resource = {}
            for resource_name, requested_files in retry_plan["files_by_resource"].items():
                item = items_by_name.get(resource_name)
                remaining = []
                if item is None:
                    remaining.extend(requested_files)
                else:
                    for failure in item.get("failed_downloads", []):
                        file_name = str(failure.get("file") or "").strip() if isinstance(failure, dict) else ""
                        if file_name and file_name not in remaining:
                            remaining.append(file_name)
                    for pending in item.get("retry_pending_files", []):
                        file_name = str(pending or "").strip()
                        if file_name and file_name not in remaining:
                            remaining.append(file_name)
                if remaining:
                    remaining_by_resource[resource_name] = remaining
            remaining_count = sum(len(files) for files in remaining_by_resource.values())
            report["retry_failed"]["remaining_by_resource"] = remaining_by_resource
            report["retry_failed"]["remaining_files"] = remaining_count
            report["summary"]["retry_remaining_files"] = remaining_count

    try:
        if retry_plan_error:
            raise RuntimeError(retry_plan_error)
        if args.vertex_fix and not decrypt_enabled:
            raise RuntimeError("顶点修复依赖 FXAP 解密；选择不解密时不能同时启用顶点修复。")
        os.chdir(work_dir)
        output_space = output_guard.check(force=True)
        temp_space = work_guard.check(force=True)
        report["storage"]["output_initial_free_gb"] = output_space["free_gb"]
        report["storage"]["temp_initial_free_gb"] = temp_space["free_gb"]

        print("=== FiveM 服务器 Dump 与 FXAP 解密工具 ===")
        feature_text = "包含服务器 Dump"
        if decrypt_enabled:
            feature_text += "、FXAP 解密"
        else:
            feature_text += "、原始 FXAP 资源完整保留（不解密）"
        if args.vertex_fix:
            feature_text += "、解密后顶点修复副本"
        print(f"功能范围: {feature_text}；不包含完整模型修复。")
        if args.vertex_fix:
            print(f"[顶点修复提示] {VERTEX_FIX_DISCLAIMER}")
        print(f"[存储] 输出目录: {output_dir}")
        print(f"[存储] 临时工作区: {work_dir}")
        print(
            f"[存储] 输出盘剩余 {output_space['free_gb']} GB，临时盘剩余 {temp_space['free_gb']} GB，"
            f"安全保留 {minimum_free_gb} GB。"
        )
        print("[存储] 默认逐资源下载、执行所选处理并清理临时文件，不再把整个服务器临时数据堆在工具安装盘。")
        print()

        if decrypt_enabled:
            emit_progress(2, "java", "正在检测 Java 环境。")
            java_info = resolve_java_executable(args.java)
            java_info["requested"] = args.java or ""
            java_info["required"] = True
            report["java"] = java_info
            print(f"[Java] 已就绪: {java_info['version']} ({java_info['path']})")
            if int(java_info.get("major", 0)) < JAVA_RECOMMENDED_MAJOR:
                print(f"[Java] 当前版本可用，推荐升级到 Java {JAVA_RECOMMENDED_MAJOR}。")
        else:
            java_info = {
                "ok": False,
                "required": False,
                "requested": args.java or "",
                "path": "",
                "version": "",
                "major": None,
            }
            report["java"] = java_info
            emit_progress(2, "raw", "本次不解密 FXAP，无需 Java 环境。")
            print("[Java] 本次选择保留原始资源，不执行 FXAP 解密，无需 Java。")

        target = (args.target or "").strip()
        if not target and not args.non_interactive:
            target = input("请输入 cfx.re 链接或 IP:端口: ").strip()
        if not target:
            raise RuntimeError("缺少目标地址，请输入 cfx.re 链接或 IP:端口。")
        report["target"] = target

        resources_choice = list(retry_plan["files_by_resource"].keys()) if retry_plan else (load_resource_selection_file(args.resources_file) if args.resources_file else args.resources)
        if args.non_interactive and not resources_choice and not retry_plan:
            resources_choice = "all"
        report["resources_requested"] = resources_choice or ""
        if retry_plan:
            print(
                f"[补充下载] 来源报告: {retry_plan['source_report']}；"
                f"资源 {len(retry_plan['files_by_resource'])} 个，失败文件 {retry_plan['requested_files']} 个。"
            )

        token = choose_token(args)

        emit_progress(15, "resolve", "正在解析服务器地址。")
        endpoint = resolve_server_endpoint(target)
        report["server_address"] = endpoint["address"]
        report["base_url"] = endpoint["base_urls"][0]
        print(f"[地址] 服务器地址: {endpoint['address']}")

        next_stage_text = "逐资源进行 FXAP 解密" if decrypt_enabled else "逐资源完整保留原始内容"
        emit_progress(24, "dump", f"开始服务器 Dump，并{next_stage_text}。")
        decryptor = FiveMDecryptor(
            output_dir=str(output_dir),
            java_executable=java_info["path"],
            work_guard=work_guard,
            output_guard=output_guard,
            require_java=decrypt_enabled,
        )
        dumper = FiveMDumper(
            report["base_url"],
            token,
            max_workers=15,
            work_guard=work_guard,
            keep_temp=args.keep_temp,
            fallback_base_urls=endpoint["base_urls"][1:],
            retry_files_by_resource=retry_plan["files_by_resource"] if retry_plan else None,
            include_decrypt_prerequisites=bool(retry_plan and decrypt_enabled),
            retry_resource_is_fxap=retry_plan["resource_is_fxap"] if retry_plan else None,
        )

        def process_ready_resource(resource_path, resource_name, dump_item):
            if decrypt_enabled:
                if retry_plan:
                    prior_fxap_state = retry_plan["resource_is_fxap"].get(resource_name)
                    has_fxap = os.path.isfile(os.path.join(resource_path, ".fxap"))
                    prerequisite_uncertain = prior_fxap_state is None and dump_item.get("retry_prerequisite_failed")
                    if not has_fxap and (prior_fxap_state is True or prerequisite_uncertain):
                        failed_names = {
                            str(failure.get("file") or "").replace("\\", "/").casefold()
                            for failure in dump_item.get("failed_downloads", [])
                        }
                        pending = []
                        for file_name in dump_item.get("retry_requested_files", []):
                            normalized = str(file_name).replace("\\", "/").casefold()
                            if normalized not in failed_names and file_name not in pending:
                                pending.append(file_name)
                        dump_item["retry_pending_files"] = pending
                        dumper.summary["retry_remaining_files"] += len(pending)
                        message = (
                            f"补充下载未获得 {resource_name} 的 .fxap 解密上下文；"
                            f"已下载的 {len(pending)} 个文件暂未写入解密输出，下次补充会继续处理。"
                        )
                        decryptor.record_retry_prerequisite_failure(resource_name, message, is_fxap=True)
                        return
                print(f"[流水线] Dump 完成，立即处理 FXAP 并释放临时文件: {resource_name}")
                decryptor.decrypt_resource(resource_path, resource_name)
            else:
                print(f"[流水线] Dump 完成，立即完整复制原始资源（含 .fxap）并释放临时文件: {resource_name}")
                raw_item = decryptor.preserve_raw_resource(
                    resource_path,
                    resource_name,
                    source_complete=int(dump_item.get("failed_files", 0) or 0) == 0,
                    source_failed_files=int(dump_item.get("failed_files", 0) or 0),
                )
                if retry_plan and raw_item.get("status") == "raw_preserved":
                    raw_item["status"] = "raw_supplemented"
                    raw_item["retry_supplement"] = True

        dumper.run(resources_choice, on_resource_ready=process_ready_resource)
        report["base_url"] = dumper.base_url
        print("[Dump] 服务器 Dump 阶段完成。")
        if decrypt_enabled:
            emit_progress(88, "fxap", "逐资源 FXAP 解密阶段完成。")
            print("[FXAP] FXAP 解密流程结束。")
        else:
            emit_progress(88, "raw", "原始资源完整保留阶段完成。")
            print("[原始保留] 未执行 FXAP 解密，完整资源目录已复制到输出。")

        if args.vertex_fix:
            emit_progress(90, "vertex_fix", "正在复制已解密的 FXAP 完整资源并执行顶点修复。")
            try:
                report["vertex_fix"] = run_vertex_fix(
                    decryptor.resource_reports,
                    output_dir,
                    output_guard=output_guard,
                )
                for warning in report["vertex_fix"].get("warnings", []):
                    report["warnings"].append(warning)
                if report["vertex_fix"].get("status") == "success":
                    emit_progress(94, "vertex_fix", "顶点修复副本已生成。")
                elif report["vertex_fix"].get("status") == "skipped":
                    emit_progress(94, "vertex_fix", "没有符合条件的 FXAP 资源，已跳过顶点修复。")
                else:
                    emit_progress(94, "vertex_fix", "顶点修复副本已生成，但存在失败项，请查看报告。")
            except Exception as exc:
                message = f"顶点修复阶段失败，原解密输出未受影响: {exc}"
                print_warning(message)
                report["vertex_fix"]["status"] = "failed"
                report["vertex_fix"]["warnings"].append(message)
                report["warnings"].append(message)

    except ResourceSelectionCancelled as exc:
        exit_code = 3
        report["status"] = "cancelled"
        message = str(exc)
        report["warnings"].append(message)
        print_warning(message)
    except DiskSpaceError as exc:
        exit_code = 12
        report["status"] = "error"
        message = f"磁盘空间不足，任务已停止，未继续刷重复失败: {exc}"
        report["errors"].append(message)
        print_error(message)
    except Exception as exc:
        exit_code = 2
        report["status"] = "error"
        message = str(exc)
        report["errors"].append(message)
        print_error(message)
    finally:
        update_report_summaries()
        summary = report.get("summary") or {}
        if report["status"] == "running":
            if int(summary.get("errors", 0)) > 0:
                report["status"] = "error"
                if exit_code == 0:
                    exit_code = 10
            elif int(summary.get("failed_files", 0)) > 0 or int(summary.get("warnings", 0)) > 0:
                report["status"] = "partial"
                if exit_code == 0:
                    exit_code = 10
            else:
                report["status"] = "success"

        try:
            cleanup_temp(work_dir, args.keep_temp)
        except Exception as exc:
            message = f"临时工作区清理失败: {exc}"
            print_warning(message)
            report["warnings"].append(message)
            if exit_code == 0:
                exit_code = 10

        try:
            report["storage"]["output_final_free_gb"] = format_gb(shutil.disk_usage(str(output_dir)).free)
        except Exception:
            report["storage"]["output_final_free_gb"] = ""

        report["finished_at"] = now_iso()
        report["elapsed_seconds"] = round(time.time() - start_time, 2)
        emit_progress(94, "report", "正在生成本次报告。")
        try:
            write_reports(report, json_path, markdown_path)
            print(f"[报告] JSON: {json_path}")
            print(f"[报告] Markdown: {markdown_path}")
        except Exception as exc:
            print_error(f"报告生成失败: {exc}")
            report["errors"].append(f"报告生成失败: {exc}")
            if exit_code == 0:
                exit_code = 10
        emit_progress(100, "done", "任务结束。")
        print("[完成] 脚本已结束，请查看输出目录和本次报告。")
        print(json.dumps(report, ensure_ascii=False), flush=True)

    return exit_code


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.list_resources:
        return run_resource_listing(args)
    return run_tool(args)


if __name__ == "__main__":
    sys.exit(main())
