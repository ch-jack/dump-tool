import sys
import os
import re
import psutil
import ctypes
import ctypes.wintypes as wintypes
import requests
import base64
import hmac
import hashlib
import subprocess
import json
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import unpad
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_GUARD = 0x100

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
SIZE_T = ctypes.c_size_t

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       wintypes.LPVOID),
        ('AllocationBase',    wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize',        SIZE_T),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
    ]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = SIZE_T
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                           ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                              wintypes.LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]

def find_fivem_process():
    pattern = re.compile(r"FiveM(_b\d+)?_GTAProcess", re.IGNORECASE)
    for proc in psutil.process_iter(attrs=['pid','name']):
        try:
            if pattern.match(proc.info['name']):
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def get_token():
    proc = find_fivem_process()
    if not proc:
        raise RuntimeError("Processus FiveM non trouvé")

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
    if not handle:
        raise RuntimeError("Impossible d'ouvrir le processus FiveM")

    token_marker = b"X-CitizenFX-Token: "
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if (mbi.State == MEM_COMMIT
            and (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY))
            and not (mbi.Protect & PAGE_GUARD)):

            if mbi.RegionSize > 64 * 1024 * 1024:
                address += mbi.RegionSize
                continue

            buffer = (ctypes.c_char * mbi.RegionSize)()
            bytesRead = SIZE_T()

            if ReadProcessMemory(handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
                data = bytes(buffer)[:bytesRead.value]
                idx = data.find(token_marker)
                if idx != -1:
                    end = data.find(b"\x00", idx)
                    if end == -1: end = idx + 100
                    token = data[idx:end].decode("ascii", errors="ignore")
                    return token.replace("X-CitizenFX-Token:", "").strip()

        address += mbi.RegionSize
    return None

def get_ip_from_cfx(link):
    try:
        if not link.startswith("http"):
            link = "https://" + link
        res = requests.get(link, timeout=15)
        res.raise_for_status()
        ip = res.headers.get("x-citizenfx-url")
        if not ip:
            raise RuntimeError("Aucun en-tête X-CitizenFX-Url trouvé")
        return ip.replace("https://","").replace("http://","").rstrip("/")
    except Exception as e:
        print(f"❌ Erreur lors de la récupération de l'IP depuis {link}: {e}")
        print("⚠️ Tentative avec l'IP par défaut...")
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+)', link)
        if ip_match:
            return ip_match.group(1)
        raise e

def safe_name(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', "_", name)

class FiveMDumper:
    def __init__(self, base_url, token, max_workers=10):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"X-CitizenFX-Token": token, "User-Agent": "CitizenFX/1"})
        self.max_workers = max_workers

    def xor_bytes(self, data: bytes) -> bytes:
        key = bytes([0x69] * 16)
        return bytes(b ^ key[i % 16] for i, b in enumerate(data[:32]))

    def get_configuration(self):
        url = f"{self.base_url}/client"
        data = {"method": "getConfiguration"}
        resp = self.session.post(url, data=data, timeout=30)
        resp.raise_for_status()
        js = resp.json()

        os.makedirs("Resources", exist_ok=True)
        with open("Resources/Grants.txt", "w", encoding="utf-8") as f:
            f.write(js.get("grants_token",""))
        return js.get("resources", [])

    def download_and_decrypt(self, url, key, iv, out_path):
        try:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()

            dec = None
            try:
                cipher = ChaCha20.new(key=key, nonce=iv)
                dec = cipher.decrypt(resp.content)
            except Exception:
                try:
                    cipher = ChaCha20.new(key=key, nonce=iv[:8])
                    dec = cipher.decrypt(resp.content)
                except Exception as e:
                    print(f"⚠️ Échec du déchiffrement ChaCha20 pour {os.path.basename(out_path)}: {e}")
                    return None

            if out_path.lower().endswith(".rpf") and not dec.startswith(b"RPF"):
                print(f"⚠️ En-tête RPF invalide pour {os.path.basename(out_path)}, mais on continue...")

            try:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f: f.write(dec)
                return out_path
            except Exception as e:
                print(f"❌ Erreur d'écriture du fichier {os.path.basename(out_path)}: {e}")
                return None
        except Exception as e:
            print(f"❌ Erreur de téléchargement pour {os.path.basename(out_path)}: {e}")
            return None

    def unpack_rpf(self, rpf_path, out_dir):
        try:
            unpacker = os.path.abspath("Bin/Unpacker.exe")
            rpf_path = os.path.abspath(rpf_path)
            out_dir = os.path.abspath(out_dir)
            
            if not os.path.exists(unpacker):
                print(f"⚠️ Unpacker.exe introuvable dans Bin/, ignorer le dépaquetage de {os.path.basename(rpf_path)}")
                return
                
            os.makedirs(out_dir, exist_ok=True)

            proc = subprocess.run(
                f'"{unpacker}" "{rpf_path}" "{out_dir}"',
                shell=True, capture_output=True, text=True, encoding="utf-8", errors="ignore"
            )
            if proc.stdout.strip():
                print(proc.stdout.strip())
            if proc.stderr.strip():
                print("stderr:", proc.stderr.strip())
            if "Extraído:" in proc.stdout or "Extracted:" in proc.stdout:
                print(f"✔ Dépaquetage de {os.path.basename(rpf_path)} → {out_dir}")
            else:
                print(f"⚠️ Échec du dépaquetage de {os.path.basename(rpf_path)} (code {proc.returncode}), mais on continue...")

            try:
                manifest_path = os.path.join(out_dir, "fxmanifest.lua")
                stream_dir = os.path.join(out_dir, "stream")
                print("\n📦 Résumé de la ressource:")
                print("Chemin:", out_dir)

                if os.path.exists(manifest_path):
                    print(" • fxmanifest.lua ✅")
                if os.path.isdir(stream_dir):
                    stream_files = os.listdir(stream_dir)
                    print(" • Fichiers stream:", ", ".join(stream_files) if stream_files else "aucun")
                for fname in os.listdir(out_dir):
                    if fname != "stream":
                        print(" •", fname)
            except Exception as e:
                print(f"⚠️ Erreur lors de l'affichage du résumé: {e}")
        except Exception as e:
            print(f"❌ Erreur lors du dépaquetagede {os.path.basename(rpf_path)}: {e}, mais on continue...")

    def fetch_resource(self, res):
        uri = base64.b64decode(res["uri"].split("#")[1])
        xored_key = uri[19:]
        iv = uri[53:61]
        hmac_key = self.xor_bytes(xored_key)[:32]

        res_name = safe_name(res["name"])
        temp_dir = os.path.join("Temp", res_name)
        unpacked_dir = os.path.join("Unpacked", res_name)

        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            for fname,hsh in (res.get("files") or {}).items():
                url = f"{res.get('fileServer') or self.base_url+'/files'}/{res['name']}/{quote(fname)}?hash={hsh}"
                rpf_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
                out_path = os.path.join(temp_dir if fname.endswith(".rpf") else unpacked_dir, fname)
                fut = exe.submit(self.download_and_decrypt, url, rpf_key, iv, out_path)
                tasks.append((fut,fname,out_path))

            for fname,body in (res.get("streamFiles") or {}).items():
                url = f"{res.get('fileServer') or self.base_url+'/files'}/{res['name']}/{quote(fname)}?hash={body['hash']}"
                s_key = hmac.new(hmac_key, fname.encode(), hashlib.sha256).digest()
                out_path = os.path.join(unpacked_dir,"stream",fname)
                fut = exe.submit(self.download_and_decrypt, url, s_key, iv, out_path)
                tasks.append((fut,fname,out_path))

            rpf_files = []
            for fut,fname,out_path in tasks:
                try:
                    path = fut.result()
                    if path: 
                        print("✔",fname)
                        if fname.endswith(".rpf") and path:
                            rpf_files.append(path)
                    else:
                        print("⚠️",fname,"- téléchargement échoué, mais on continue")
                except Exception as e:
                    print("❌",fname,":",e,"- mais on continue")
        for rpf_path in rpf_files:
            if os.path.exists(rpf_path):
                self.unpack_rpf(rpf_path, unpacked_dir)
            else:
                print(f"⚠️ Fichier RPF introuvable: {rpf_path}, ignoré")

    def run(self):
        resources = self.get_configuration()
        print("📦 Ressources:")
        for i,res in enumerate(resources):
            print(i,res["name"])
        choice = input("Sélectionnez les indices (ex: 2,6,22,42,51) ou 'all': ").strip()
        chosen = resources if choice.lower()=="all" else [resources[int(x)] for x in choice.split(",") if x.strip().isdigit()]
        for res in chosen:
            self.fetch_resource(res)

class FiveMDecryptor:
    def __init__(self):
        self.DefaultKey = bytes([
            0xb3, 0xcb, 0x2e, 0x04, 0x87, 0x94, 0xd6, 0x73, 0x08, 0x23, 0xc4, 0x93, 0x7a, 0xbd, 0x18, 0xad,
            0x6b, 0xe6, 0xdc, 0xb3, 0x91, 0x43, 0x0d, 0x28, 0xf9, 0x40, 0x9d, 0x48, 0x37, 0xb9, 0x38, 0xfb
        ])
        self.HeaderToVerify = b"FXAP"
        self.AesKey = bytes([
            0x7a, 0xba, 0x8d, 0x53, 0x25, 0x5b, 0x0e, 0xfd, 0x16, 0xbd, 0x35, 0x22, 0xa0, 0xb9, 0x26, 0xa5,
            0x61, 0x83, 0x2e, 0xec, 0xa2, 0x4b, 0xfd, 0x56, 0x9e, 0xc0, 0x1d, 0x8f, 0x38, 0x40, 0x54, 0x6d
        ])
        self.LuaHeaderHex = "1b4c7561540019930d0a1a0a040808785"  
        self.OutputDir = "Output"
        self.TempDir = "TempCompiled"
        self.KeymasterUrl = "https://keymaster.fivem.net/api/validate"

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
            iv = hexdata[ivPtr:ivPtr+12]
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
            except Exception as e:
                raise RuntimeError(f"ChaCha20 decrypt failed: {e}")

    def calculate_client_key(self, grants_clk: bytes):
        iv = grants_clk[:16]
        enc = grants_clk[16:]
        cipher = AES.new(self.AesKey, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc)
        try:
            return unpad(decrypted, AES.block_size)
        except ValueError:
            return decrypted

    def process_lua_file(self, decrypted_buffer: bytes, output_path: str, resourceName: str, file_rel: str):
        tmp_path = os.path.join(self.TempDir, f"{resourceName}/{file_rel}c")
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        with open(tmp_path, "wb") as f:
            f.write(decrypted_buffer)
        final_path = output_path
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        try:
            cmd = f'java -jar Tools/Decompile/unluac54.jar "{tmp_path}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if proc.returncode != 0:
                fname = os.path.basename(final_path)
                name_only = os.path.splitext(fname)[0]
                errfile = os.path.join(os.path.dirname(final_path), f"error_{name_only}_unluac.txt")
                with open(errfile, "w", encoding="utf-8", errors="ignore") as ef:
                    ef.write(proc.stderr or proc.stdout or "Unknown unluac error")
            else:
                with open(final_path, "w", encoding="utf-8", errors="ignore") as out:
                    out.write(proc.stdout)
        except Exception as e:
            with open(final_path, "wb") as out:
                out.write(decrypted_buffer)
            print(f"unluac failed for {final_path}: {e}")

    def get_all_files(self, dirpath):
        results = []
        for root, _, files in os.walk(dirpath):
            for f in files:
                results.append(os.path.join(root, f))
        return results

    def decrypt_resource_file(self, resourcePath, relativeFile, decryptKey, resourceName, grantsClk):
        try:
            full_path = os.path.join(resourcePath, relativeFile)
            output_path = os.path.join(self.OutputDir, resourceName, relativeFile)

            if not os.path.exists(full_path):
                print(f"⚠️ Fichier introuvable: {relativeFile}, ignoré")
                return
            if not self.verify_encrypted(full_path):
                try:
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    with open(full_path, "rb") as inf, open(output_path, "wb") as outf:
                        outf.write(inf.read())
                    return
                except Exception as e:
                    print(f"⚠️ Erreur de copie du fichier {relativeFile}: {e}")
                    return

            decrypted_file = self.decrypt_file(full_path, self.DefaultKey)
            if not decrypted_file:
                print(f"⚠️ Échec du déchiffrement initial de {relativeFile}, ignoré")
                return

            decrypted_buffer = self.decrypt_buffer(decrypted_file, decryptKey)
            alternative_key = self.calculate_client_key(grantsClk)

            if decrypted_buffer is None:
                print(f"⚠️ Échec du déchiffrement du buffer de {relativeFile}, ignoré")
                return
        except Exception as e:
            print(f"❌ Erreur générale lors du traitement de {relativeFile}: {e}")
            return

        if relativeFile.lower().endswith(".lua"):
            is_lua = decrypted_buffer.hex().startswith(self.LuaHeaderHex)
            if is_lua:
                self.process_lua_file(decrypted_buffer, output_path, resourceName, relativeFile)
            else:
                decrypted_alt = None
                try:
                    decrypted_alt = self.decrypt_buffer(decrypted_file, decryptKey, bufferPtr=90, ivPtr=78)
                except Exception:
                    decrypted_alt = None

                if decrypted_alt and decrypted_alt.hex().startswith(self.LuaHeaderHex):
                    self.process_lua_file(decrypted_alt, output_path, resourceName, relativeFile)
                else:
                    try:
                        decrypted_alt2 = self.decrypt_buffer(decrypted_file, alternative_key)
                        if decrypted_alt2:
                            self.process_lua_file(decrypted_alt2, output_path, resourceName, relativeFile)
                        else:
                            os.makedirs(os.path.dirname(output_path), exist_ok=True)
                            with open(output_path, "wb") as out:
                                out.write(decrypted_buffer)
                    except Exception as e:
                        print(f"⚠️ Erreur de déchiffrement lua {relativeFile}: {e}, mais on continue")
        else:
            try:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "wb") as out:
                    out.write(decrypted_buffer)
            except Exception as e:
                print(f"⚠️ Erreur d'écriture du fichier {relativeFile}: {e}")

    def get_directories(self, source):
        return [os.path.join(source, d) for d in os.listdir(source) if os.path.isdir(os.path.join(source, d))]

    def validate_key_from_file(self, grants_path):
        with open(grants_path, "r", encoding="utf-8") as f:
            grants_token = f.read().strip()
        return {"success": True, "grants_token": grants_token}

    def decrypt_resource(self, resourcePath, resourceName, grants_token=None):
        try:
            fxap_file = os.path.join(resourcePath, ".fxap")
            if not os.path.exists(fxap_file):
                try:
                    for file_full in self.get_all_files(resourcePath):
                        try:
                            relative = os.path.relpath(file_full, resourcePath).replace("\\", "/")
                            output_path = os.path.join(self.OutputDir, resourceName, relative)
                            os.makedirs(os.path.dirname(output_path), exist_ok=True)
                            with open(file_full, "rb") as inf, open(output_path, "wb") as outf:
                                outf.write(inf.read())
                        except Exception as e:
                            print(f"⚠️ Erreur de copie du fichier {os.path.basename(file_full)}: {e}")
                    print(f"[+] Ressource non-chiffrée copiée: {resourceName}")
                    return
                except Exception as e:
                    print(f"❌ Erreur lors de la copie de la ressource {resourceName}: {e}")
                    return
        except Exception as e:
            print(f"❌ Erreur générale pour la ressource {resourceName}: {e}")
            return


        fxap_buffer = self.decrypt_file(fxap_file, self.DefaultKey)
        if not fxap_buffer:
            return

        resource_id = self.scan_for_id(fxap_buffer)

        if grants_token is None:
            grants_path = os.path.join("Resources", "Grants.txt")
            if not os.path.exists(grants_path):
                print("Aucun fichier Grants.txt trouvé; impossible de déchiffrer la ressource", resourceName)
                return
            data = self.validate_key_from_file(grants_path)
        else:
            data = {"success": True, "grants_token": grants_token}

        if not data.get("success"):
            print("Échec de validation de la clé pour", resourceName)
            return

        try:
            payload_part = data["grants_token"].split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            payload = json.loads(base64.b64decode(payload_part).decode('utf-8'))
        except Exception as e:
            print("Échec de l'analyse du payload du token grants:", e)
            return

        if str(resource_id) not in payload.get("grants", {}):
            print(f"Ressource non autorisée {resourceName} (ID {resource_id})")
            return

        decrypt_key = bytes.fromhex(payload["grants"][str(resource_id)])
        grants_clk_hex = payload["grants_clk"][str(resource_id)]
        grants_clk = bytes.fromhex(grants_clk_hex)

        print(f"Déchiffrement: {resourceName} (ID: {resource_id})")

        files = self.get_all_files(resourcePath)
        tasks = []
        with ThreadPoolExecutor(max_workers=6) as exe:
            for file_full in files:
                if file_full.endswith(".fxap"):
                    continue
                relative = os.path.relpath(file_full, resourcePath).replace("\\", "/")
                tasks.append(exe.submit(self.decrypt_resource_file, resourcePath, relative, decrypt_key, resourceName, grants_clk))

            for t in tasks:
                try:
                    t.result()
                except Exception as e:
                    print("Erreur lors du déchiffrement du fichier:", e)

    def decrypt_all_resources(self):
        resource_dirs = []
        resources_root = "Unpacked"
        if not os.path.isdir(resources_root):
            print("Aucun dossier Unpacked/ trouvé - exécutez d'abord le dumper/décompresseur.")
            return
        for entry in os.listdir(resources_root):
            full = os.path.join(resources_root, entry)
            if os.path.isdir(full):
                resource_dirs.append(full)
        for resource_dir in resource_dirs:
            resource_name = os.path.basename(resource_dir)
            self.decrypt_resource(resource_dir, resource_name)

    def start(self):
        print("Démarrage du déchiffrement des ressources...")
        self.decrypt_all_resources()
        print("Déchiffrement terminé!")

if __name__=="__main__":
    print("=== FiveM Resource Dumper & Decryptor ===")
    print()
    
    print("Sélectionnez votre méthode de token : ")
    print("1. Scanner automatiquement depuis FiveM ")
    print("2. Entrer un token personnalisé ")
    
    token_choice = input("Votre choix (1 ou 2) : ").strip()
    
    token = None
    if token_choice == "2":
        token = input("Entrez votre token personnalisé : ").strip()
        if not token:
            sys.exit("Token vide. Arrêt du programme.")
        print(f"[*] Token personnalisé utilisé : {token[:20]}...")
    else:
        print("[*] Scan du processus FiveM pour récupérer le token...")
        token = get_token()
        if not token:
            print("❌ Token non trouvé dans le processus FiveM.")
            fallback = input("Voulez-vous entrer un token manuellement? (o/n): ").strip().lower()
            if fallback in ['o', 'oui', 'y', 'yes']:
                token = input("Entrez votre token: ").strip()
                if not token:
                    sys.exit("Token vide. Arrêt du programme.")
            else:
                sys.exit("Aucun token disponible. Assurez-vous que FiveM est en cours d'exécution et connecté.")
        print(f"[*] Token scanné: {token[:20]}...")
    
    print()

    if len(sys.argv) < 2:
        link = input("Entrez le lien cfx.re : ").strip()
    else:
        link = sys.argv[1]

    ip = get_ip_from_cfx(link)
    print("[*] IP du serveur : ", ip)

    try:
        base_url = "https://"+ip
        dumper = FiveMDumper(base_url, token, max_workers=15)
        print("\n🔄 Démarrage du dumper...")
        dumper.run()
        print("✅ Dumper terminé !")
    except Exception as e:
        print(f"❌ Erreur lors du dumping: {e}")
        print("⚠️ On continue avec le déchiffrement si possible...")

    try:
        print("\n🔄 Démarrage du déchiffrement...")
        decryptor = FiveMDecryptor()
        if len(sys.argv) >= 3:
            decryptor.start()
        else:
            decryptor.start()
        print("✅ Déchiffrement terminé !")
    except Exception as e:
        print(f"❌ Erreur lors du déchiffrement: {e}")
        print("⚠️ On continue avec le nettoyage...")

    try:
        print("\n🧹 Nettoyage des fichiers temporaires...")
        import shutil
        for folder in ["Temp", "Unpacked", "TempCompiled", "Resources"]:
            if os.path.isdir(folder):
                try:
                    shutil.rmtree(folder)
                    print(f"🧹 Nettoyage de {folder}/")
                except Exception as e:
                    print(f"⚠️ Impossible de supprimer {folder}/: {e}")
    except Exception as e:
        print(f"❌ Erreur lors du nettoyage: {e}")
    
    print("\n✅ Script terminé ! Vérifiez le dossier Output/ pour les résultats.")

