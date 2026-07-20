import argparse
import base64
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
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

TOOL_VERSION = "1.1.0"
SCRIPT_DIR = Path(__file__).resolve().parent
TEMP_FOLDERS = ["Temp", "Unpacked", "TempCompiled", "Resources"]

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


def emit_progress(percent, stage, message):
    payload = {
        "percent": max(0, min(100, int(percent))),
        "stage": str(stage),
        "message": str(message),
    }
    print("CK_PROGRESS " + json.dumps(payload, ensure_ascii=False), flush=True)


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


def mask_token(token):
    if not token:
        return ""
    if len(token) <= 12:
        return token[:3] + "***"
    return token[:8] + "..." + token[-4:]


def print_warning(message):
    print(f"[警告] {message}", flush=True)


def print_error(message):
    print(f"[错误] {message}", flush=True)


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

    token_marker = b"X-CitizenFX-Token: "
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
                    idx = data.find(token_marker)
                    if idx != -1:
                        end = data.find(b"\x00", idx)
                        if end == -1:
                            end = idx + 160
                        token = data[idx:end].decode("ascii", errors="ignore")
                        return token.replace("X-CitizenFX-Token:", "").strip()

            if mbi.RegionSize <= 0:
                break
            address += mbi.RegionSize
    finally:
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass

    return None


def get_ip_from_cfx(target):
    direct = direct_server_address(target)
    if direct:
        print(f"[地址] 使用直连服务器地址: {direct}")
        return direct

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
        if direct:
            print(f"[地址] 已从 cfx.re 解析到服务器: {direct}")
            return direct

        cleaned = re.sub(r"^https?://", "", header.strip(), flags=re.I).rstrip("/")
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})", cleaned)
        if match:
            direct = direct_server_address(match.group(1))
            if direct:
                print(f"[地址] 已从 cfx.re 解析到服务器: {direct}")
                return direct

        raise RuntimeError(f"解析到的服务器地址无效: {header}")
    except Exception as exc:
        raise RuntimeError(f"从 {link} 解析服务器地址失败: {exc}") from exc


class FiveMDumper:
    def __init__(self, base_url, token, max_workers=10):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"X-CitizenFX-Token": token, "User-Agent": "CitizenFX/1"})
        self.max_workers = max_workers
        self.summary = {
            "resources_total": 0,
            "resources_selected": 0,
            "downloaded_files": 0,
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

    def get_configuration(self):
        emit_progress(22, "server_config", "正在向服务器请求资源配置。")
        url = f"{self.base_url}/client"
        data = {"method": "getConfiguration"}
        resp = self.session.post(url, data=data, timeout=30)
        resp.raise_for_status()
        js = resp.json()

        os.makedirs("Resources", exist_ok=True)
        with open("Resources/Grants.txt", "w", encoding="utf-8") as f:
            f.write(js.get("grants_token", ""))
        resources = js.get("resources", []) or []
        self.summary["resources_total"] = len(resources)
        print(f"[配置] 服务器返回 {len(resources)} 个资源。")
        return resources

    def download_and_decrypt(self, url, key, iv, out_path, file_name):
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()

            try:
                cipher = ChaCha20.new(key=key, nonce=iv)
                dec = cipher.decrypt(resp.content)
            except Exception:
                try:
                    cipher = ChaCha20.new(key=key, nonce=iv[:8])
                    dec = cipher.decrypt(resp.content)
                except Exception as exc:
                    return {"path": None, "file": file_name, "error": f"ChaCha20 解密失败: {exc}"}

            if out_path.lower().endswith(".rpf") and not dec.startswith(b"RPF"):
                print_warning(f"{file_name} 的 RPF 文件头不完整，继续保存并尝试后续处理。")

            try:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(dec)
                return {"path": out_path, "file": file_name, "bytes": len(dec), "error": ""}
            except Exception as exc:
                return {"path": None, "file": file_name, "error": f"写入文件失败: {exc}"}
        except Exception as exc:
            return {"path": None, "file": file_name, "error": f"下载失败: {exc}"}

    def unpack_rpf(self, rpf_path, out_dir, item):
        unpacker = os.path.abspath("Bin/Unpacker.exe")
        rpf_path = os.path.abspath(rpf_path)
        out_dir = os.path.abspath(out_dir)

        if not os.path.exists(unpacker):
            self.warn(item, f"未找到 Bin/Unpacker.exe，跳过 RPF 解包: {os.path.basename(rpf_path)}")
            return False

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

            extracted = "Extraído:" in proc.stdout or "Extracted:" in proc.stdout or proc.returncode == 0
            if extracted:
                print(f"[解包完成] {os.path.basename(rpf_path)} -> {out_dir}")
                self.summary["rpf_unpacked"] += 1
                item["rpf_unpacked"] += 1
                self.print_resource_summary(out_dir)
                return True

            self.warn(item, f"RPF 解包失败: {os.path.basename(rpf_path)}，退出码 {proc.returncode}。")
            return False
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
        item = {
            "name": resource_name,
            "safe_name": res_name,
            "status": "pending",
            "files_total": 0,
            "downloaded_files": 0,
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
            item["status"] = "failed"
            self.resource_reports.append(item)
            return item

        temp_dir = os.path.join("Temp", res_name)
        unpacked_dir = os.path.join("Unpacked", res_name)
        file_jobs = []

        files = res.get("files") or {}
        stream_files = res.get("streamFiles") or {}
        item["files_total"] = len(files) + len(stream_files)

        for fname, hsh in files.items():
            url = f"{res.get('fileServer') or self.base_url + '/files'}/{res['name']}/{quote(fname)}?hash={hsh}"
            rpf_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
            out_path = os.path.join(temp_dir if fname.endswith(".rpf") else unpacked_dir, fname)
            file_jobs.append((fname, url, rpf_key, iv, out_path))

        for fname, body in stream_files.items():
            url = f"{res.get('fileServer') or self.base_url + '/files'}/{res['name']}/{quote(fname)}?hash={body['hash']}"
            s_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
            out_path = os.path.join(unpacked_dir, "stream", fname)
            file_jobs.append((fname, url, s_key, iv, out_path))

        print(f"[Dump] ({index}/{total}) 正在下载资源: {resource_name}，文件 {len(file_jobs)} 个。")
        rpf_files = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            future_map = {
                exe.submit(self.download_and_decrypt, url, key, iv_value, out_path, fname): (fname, out_path)
                for fname, url, key, iv_value, out_path in file_jobs
            }
            for future in as_completed(future_map):
                fname, out_path = future_map[future]
                completed += 1
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"path": None, "file": fname, "error": str(exc)}

                if result.get("path"):
                    item["downloaded_files"] += 1
                    self.summary["downloaded_files"] += 1
                    print(f"[下载完成] {fname}")
                    if fname.endswith(".rpf"):
                        rpf_files.append(result["path"])
                else:
                    item["failed_files"] += 1
                    self.summary["failed_files"] += 1
                    self.warn(item, f"{fname} 处理失败: {result.get('error') or '未知错误'}")

                base = 28
                span = 34
                resource_ratio = ((index - 1) + (completed / max(1, len(file_jobs)))) / max(1, total)
                emit_progress(base + int(span * resource_ratio), "dump", f"正在 Dump {resource_name}: {completed}/{len(file_jobs)}")

        for rpf_path in rpf_files:
            if os.path.exists(rpf_path):
                self.unpack_rpf(rpf_path, unpacked_dir, item)
            else:
                self.warn(item, f"RPF 文件不存在，已跳过: {rpf_path}")

        if item["failed_files"] == 0:
            item["status"] = "success"
        elif item["downloaded_files"] > 0:
            item["status"] = "partial"
        else:
            item["status"] = "failed"

        self.resource_reports.append(item)
        return item

    def select_resources(self, resources, choice):
        print("[资源列表]")
        for i, res in enumerate(resources):
            print(f"{i}: {res.get('name', '')}")

        choice = (choice or "").strip()
        if not choice:
            choice = input("请选择资源序号（例如 2,6,22）或输入 all 处理全部: ").strip()
        if choice.lower() == "all":
            return list(resources)

        selected = []
        for part in [x.strip() for x in choice.split(",") if x.strip()]:
            if part.isdigit():
                idx = int(part)
                if 0 <= idx < len(resources):
                    selected.append(resources[idx])
                else:
                    print_warning(f"资源序号越界，已忽略: {part}")
            else:
                match = next((res for res in resources if res.get("name") == part), None)
                if match:
                    selected.append(match)
                else:
                    print_warning(f"未找到资源名，已忽略: {part}")
        return selected

    def run(self, resources_choice=None):
        resources = self.get_configuration()
        chosen = self.select_resources(resources, resources_choice)
        self.summary["resources_selected"] = len(chosen)

        if not chosen:
            print_warning("没有选择任何资源，跳过 Dump。")
            return self.resource_reports

        print(f"[Dump] 将处理 {len(chosen)} 个资源。")
        for idx, res in enumerate(chosen, start=1):
            self.fetch_resource(res, idx, len(chosen))
        return self.resource_reports


class FiveMDecryptor:
    def __init__(self, output_dir="Output"):
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
        self.LuaHeaderHex = "1b4c7561540019930d0a1a0a040808785"
        self.OutputDir = str(output_dir)
        self.TempDir = "TempCompiled"
        self.KeymasterUrl = "https://keymaster.fivem.net/api/validate"
        self.summary = {
            "resources_total": 0,
            "resources_decrypted": 0,
            "resources_copied": 0,
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 0,
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
        if not hexdata:
            return None
        if bufferPtr is not None and ivPtr is not None:
            iv = hexdata[ivPtr : ivPtr + 12]
            enc = hexdata[bufferPtr:]
            return self._chacha_decrypt(enc, key, iv)
        iv = hexdata[80:92]
        enc = hexdata[92:]
        return self._chacha_decrypt(enc, key, iv)

    def _chacha_decrypt(self, enc: bytes, key: bytes, iv: bytes):
        try:
            cipher = ChaCha20.new(key=key, nonce=iv)
            return cipher.decrypt(enc)
        except Exception:
            try:
                cipher = ChaCha20.new(key=key, nonce=iv[:8])
                return cipher.decrypt(enc)
            except Exception as exc:
                raise RuntimeError(f"ChaCha20 解密失败: {exc}") from exc

    def calculate_client_key(self, grants_clk: bytes):
        iv = grants_clk[:16]
        enc = grants_clk[16:]
        cipher = AES.new(self.AesKey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc)
        try:
            return unpad(decrypted, AES.block_size)
        except ValueError:
            return decrypted

    def process_lua_file(self, decrypted_buffer: bytes, output_path: str, resource_name: str, file_rel: str):
        tmp_path = os.path.join(self.TempDir, f"{resource_name}/{file_rel}c")
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        with open(tmp_path, "wb") as f:
            f.write(decrypted_buffer)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        jar_path = os.path.abspath("Tools/Decompile/unluac54.jar")
        try:
            proc = subprocess.run(
                ["java", "-jar", jar_path, tmp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if proc.returncode != 0:
                fname = os.path.basename(output_path)
                name_only = os.path.splitext(fname)[0]
                errfile = os.path.join(os.path.dirname(output_path), f"error_{name_only}_unluac.txt")
                with open(errfile, "w", encoding="utf-8", errors="ignore") as ef:
                    ef.write(proc.stderr or proc.stdout or "unluac 未返回错误详情")
                print_warning(f"Lua 反编译失败，已写入错误文件: {errfile}")
                return "decompile_error"

            with open(output_path, "w", encoding="utf-8", errors="ignore") as out:
                out.write(proc.stdout)
            return "decompiled"
        except Exception as exc:
            with open(output_path, "wb") as out:
                out.write(decrypted_buffer)
            print_warning(f"unluac 执行失败，已保存 Lua 字节码: {output_path}，原因: {exc}")
            return "bytecode_saved"

    def get_all_files(self, dirpath):
        results = []
        for root, _, files in os.walk(dirpath):
            for f in files:
                results.append(os.path.join(root, f))
        return results

    def decrypt_resource_file(self, resource_path, relative_file, decrypt_key, resource_name, grants_clk, item):
        try:
            full_path = os.path.join(resource_path, relative_file)
            output_path = os.path.join(self.OutputDir, resource_name, relative_file)

            if not os.path.exists(full_path):
                return {"status": "missing", "file": relative_file, "error": "文件不存在"}

            if not self.verify_encrypted(full_path):
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(full_path, "rb") as inf, open(output_path, "wb") as outf:
                    outf.write(inf.read())
                return {"status": "copied", "file": relative_file, "output": output_path}

            decrypted_file = self.decrypt_file(full_path, self.DefaultKey)
            if not decrypted_file:
                return {"status": "failed", "file": relative_file, "error": "初始 FXAP 解密失败"}

            decrypted_buffer = self.decrypt_buffer(decrypted_file, decrypt_key)
            alternative_key = self.calculate_client_key(grants_clk)
            if decrypted_buffer is None:
                return {"status": "failed", "file": relative_file, "error": "资源数据解密失败"}
        except Exception as exc:
            return {"status": "failed", "file": relative_file, "error": f"处理异常: {exc}"}

        try:
            if relative_file.lower().endswith(".lua"):
                is_lua = decrypted_buffer.hex().startswith(self.LuaHeaderHex)
                if is_lua:
                    lua_status = self.process_lua_file(decrypted_buffer, output_path, resource_name, relative_file)
                    return {"status": "decrypted", "file": relative_file, "output": output_path, "lua": lua_status}

                decrypted_alt = None
                try:
                    decrypted_alt = self.decrypt_buffer(decrypted_file, decrypt_key, bufferPtr=90, ivPtr=78)
                except Exception:
                    decrypted_alt = None

                if decrypted_alt and decrypted_alt.hex().startswith(self.LuaHeaderHex):
                    lua_status = self.process_lua_file(decrypted_alt, output_path, resource_name, relative_file)
                    return {"status": "decrypted", "file": relative_file, "output": output_path, "lua": lua_status}

                try:
                    decrypted_alt2 = self.decrypt_buffer(decrypted_file, alternative_key)
                    if decrypted_alt2:
                        lua_status = self.process_lua_file(decrypted_alt2, output_path, resource_name, relative_file)
                        return {"status": "decrypted", "file": relative_file, "output": output_path, "lua": lua_status}
                except Exception as exc:
                    self.warn(item, f"Lua 备用解密失败: {relative_file}，{exc}")

            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as out:
                out.write(decrypted_buffer)
            return {"status": "decrypted", "file": relative_file, "output": output_path}
        except Exception as exc:
            return {"status": "failed", "file": relative_file, "error": f"写入失败: {exc}"}

    def validate_key_from_file(self, grants_path):
        with open(grants_path, "r", encoding="utf-8") as f:
            grants_token = f.read().strip()
        return {"success": True, "grants_token": grants_token}

    def copy_plain_resource(self, resource_path, resource_name, item):
        copied = 0
        for file_full in self.get_all_files(resource_path):
            try:
                relative = os.path.relpath(file_full, resource_path).replace("\\", "/")
                output_path = os.path.join(self.OutputDir, resource_name, relative)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(file_full, "rb") as inf, open(output_path, "wb") as outf:
                    outf.write(inf.read())
                copied += 1
            except Exception as exc:
                item["failed_files"] += 1
                self.summary["failed_files"] += 1
                self.warn(item, f"复制文件失败: {os.path.basename(file_full)}，{exc}")
        item["copied_files"] += copied
        self.summary["copied_files"] += copied
        self.summary["resources_copied"] += 1
        print(f"[复制完成] 未加密资源已复制: {resource_name}，文件 {copied} 个。")

    def decrypt_resource(self, resource_path, resource_name, grants_token=None):
        item = {
            "name": resource_name,
            "status": "pending",
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

            decrypt_key = bytes.fromhex(payload["grants"][str(resource_id)])
            grants_clk_hex = payload["grants_clk"][str(resource_id)]
            grants_clk = bytes.fromhex(grants_clk_hex)

            print(f"[FXAP] 正在解密: {resource_name} (ID: {resource_id})")

            files = [f for f in self.get_all_files(resource_path) if not f.endswith(".fxap")]
            item["files_total"] = len(files)
            tasks = []
            with ThreadPoolExecutor(max_workers=6) as exe:
                for file_full in files:
                    relative = os.path.relpath(file_full, resource_path).replace("\\", "/")
                    tasks.append(exe.submit(self.decrypt_resource_file, resource_path, relative, decrypt_key, resource_name, grants_clk, item))

                for task in as_completed(tasks):
                    try:
                        result = task.result()
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
                        self.warn(item, f"{result.get('file') or resource_name} 解密失败: {result.get('error') or '未知错误'}")

            if item["failed_files"] == 0:
                item["status"] = "decrypted"
                self.summary["resources_decrypted"] += 1
            elif item["decrypted_files"] or item["copied_files"]:
                item["status"] = "partial"
            else:
                item["status"] = "failed"

            self.resource_reports.append(item)
            return item
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

        self.summary["resources_total"] = len(resource_dirs)
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
    parser.add_argument("--resources", default=None, help="资源选择，输入 all 或逗号分隔序号/资源名；非交互模式默认 all")
    parser.add_argument("--output", default="Output", help="解密输出目录")
    parser.add_argument("--report", default="", help="报告路径。可传 report.json、report.md 或目录")
    parser.add_argument("--non-interactive", action="store_true", help="非交互模式，缺少必要信息时直接失败")
    parser.add_argument("--keep-temp", action="store_true", help="保留 Temp、Unpacked、TempCompiled、Resources 临时目录")
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
        f"- 模型修复: {'包含' if scope.get('modelRepair') else '不包含'}",
        "",
        "## 汇总",
        "",
        f"- 服务器资源总数: {summary.get('server_resources_total', 0)}",
        f"- 本次选择资源: {summary.get('server_resources_selected', 0)}",
        f"- Dump 下载成功文件: {summary.get('downloaded_files', 0)}",
        f"- RPF 解包成功: {summary.get('rpf_unpacked', 0)}",
        f"- FXAP 解密资源: {summary.get('resources_decrypted', 0)}",
        f"- 复制未加密资源: {summary.get('resources_copied', 0)}",
        f"- 输出文件数: {summary.get('output_files', 0)}",
        f"- 失败文件数: {summary.get('failed_files', 0)}",
        f"- 警告: {summary.get('warnings', 0)}",
        f"- 错误: {summary.get('errors', 0)}",
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
                f"RPF 解包 {item.get('rpf_unpacked', 0)}"
            )
            for warning in item.get("warnings", [])[:5]:
                lines.append(f"  - 警告: {warning}")
            for error in item.get("errors", [])[:5]:
                lines.append(f"  - 错误: {error}")
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

    if len(dump_resources) > 200 or len(decrypt_resources) > 200:
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


def cleanup_temp(keep_temp):
    if keep_temp:
        print("[清理] 已按参数保留临时目录。")
        return

    emit_progress(96, "cleanup", "正在清理临时目录。")
    for folder in TEMP_FOLDERS:
        if os.path.isdir(folder):
            try:
                shutil.rmtree(folder)
                print(f"[清理] 已删除 {folder}/")
            except Exception as exc:
                print_warning(f"无法删除 {folder}/: {exc}")


def choose_token(args):
    if args.token_choice == "2":
        token = (args.token or "").strip()
        if not token and not args.non_interactive:
            token = input("请输入自定义 token: ").strip()
        if not token:
            raise RuntimeError("已选择手动 token，但没有提供 token。")
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
    print(f"[Token] 已获取 token: {mask_token(token)}")
    return token


def run_tool(args):
    os.chdir(SCRIPT_DIR)
    start_time = time.time()
    started_at = now_iso()

    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = SCRIPT_DIR / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path, markdown_path = resolve_report_paths(args.report, output_dir)

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
        "resources_requested": args.resources or ("all" if args.non_interactive else ""),
        "scope": {
            "serverDump": True,
            "fxapDecrypt": True,
            "modelRepair": False,
        },
        "summary": {},
        "dump_summary": {},
        "decrypt_summary": {},
        "dump_resources": [],
        "decrypt_resources": [],
        "warnings": [],
        "errors": [],
    }

    exit_code = 0
    try:
        print("=== FiveM 服务器 Dump 与 FXAP 解密工具 ===")
        print("功能范围: 包含服务器 Dump、FXAP 解密；不包含模型修复。")
        print()

        target = (args.target or "").strip()
        if not target and not args.non_interactive:
            target = input("请输入 cfx.re 链接或 IP:端口: ").strip()
        if not target:
            raise RuntimeError("缺少目标地址，请输入 cfx.re 链接或 IP:端口。")
        report["target"] = target

        resources_choice = args.resources
        if args.non_interactive and not resources_choice:
            resources_choice = "all"
        report["resources_requested"] = resources_choice or ""

        token = choose_token(args)

        emit_progress(15, "resolve", "正在解析服务器地址。")
        server_address = get_ip_from_cfx(target)
        report["server_address"] = server_address
        report["base_url"] = "https://" + server_address
        print(f"[地址] 服务器地址: {server_address}")

        try:
            emit_progress(24, "dump", "开始服务器 Dump。")
            dumper = FiveMDumper(report["base_url"], token, max_workers=15)
            dump_resources = dumper.run(resources_choice)
            report["dump_summary"] = dumper.summary
            report["dump_resources"] = dump_resources
            print("[Dump] 服务器 Dump 阶段完成。")
        except Exception as exc:
            exit_code = 10
            message = f"服务器 Dump 阶段失败: {exc}"
            report["errors"].append(message)
            print_error(message)
            print_warning("将继续尝试 FXAP 解密已有临时文件。")

        try:
            emit_progress(62, "fxap", "开始 FXAP 解密。")
            decryptor = FiveMDecryptor(output_dir=str(output_dir))
            decrypt_resources = decryptor.start()
            report["decrypt_summary"] = decryptor.summary
            report["decrypt_resources"] = decrypt_resources
            print("[FXAP] FXAP 解密阶段完成。")
        except Exception as exc:
            exit_code = 10
            message = f"FXAP 解密阶段失败: {exc}"
            report["errors"].append(message)
            print_error(message)

        cleanup_temp(args.keep_temp)

        dump_summary = report.get("dump_summary") or {}
        decrypt_summary = report.get("decrypt_summary") or {}
        failed_files = int(dump_summary.get("failed_files", 0)) + int(decrypt_summary.get("failed_files", 0))
        warnings = int(dump_summary.get("warnings", 0)) + int(decrypt_summary.get("warnings", 0)) + len(report["warnings"])
        errors = int(dump_summary.get("errors", 0)) + int(decrypt_summary.get("errors", 0)) + len(report["errors"])
        report["summary"] = {
            "server_resources_total": int(dump_summary.get("resources_total", 0)),
            "server_resources_selected": int(dump_summary.get("resources_selected", 0)),
            "downloaded_files": int(dump_summary.get("downloaded_files", 0)),
            "rpf_unpacked": int(dump_summary.get("rpf_unpacked", 0)),
            "resources_decrypted": int(decrypt_summary.get("resources_decrypted", 0)),
            "resources_copied": int(decrypt_summary.get("resources_copied", 0)),
            "decrypted_files": int(decrypt_summary.get("decrypted_files", 0)),
            "copied_files": int(decrypt_summary.get("copied_files", 0)),
            "failed_files": failed_files,
            "warnings": warnings,
            "errors": errors,
            "output_files": count_files(output_dir),
        }

        if errors:
            report["status"] = "error"
            if exit_code == 0:
                exit_code = 10
        elif failed_files or warnings:
            report["status"] = "partial"
            if exit_code == 0:
                exit_code = 10
        else:
            report["status"] = "success"

    except Exception as exc:
        exit_code = 2
        message = str(exc)
        report["status"] = "error"
        report["errors"].append(message)
        report["summary"] = {
            "server_resources_total": 0,
            "server_resources_selected": 0,
            "downloaded_files": 0,
            "rpf_unpacked": 0,
            "resources_decrypted": 0,
            "resources_copied": 0,
            "decrypted_files": 0,
            "copied_files": 0,
            "failed_files": 0,
            "warnings": 0,
            "errors": len(report["errors"]),
            "output_files": count_files(output_dir),
        }
        print_error(message)
    finally:
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
    return run_tool(args)


if __name__ == "__main__":
    sys.exit(main())
