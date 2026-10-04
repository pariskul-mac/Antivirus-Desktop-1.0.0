import os
import math
import hashlib
import re
import base64
import time
import requests
from collections import Counter
from typing import Dict, Any, List, Optional

from quarantine_manager import quarantine_file
from yara_engine import run_yara_scan
from system_scanner_engine import verify_digital_signature

try:
    import pefile
except ImportError:
    pefile = None

MAX_FILE_SIZE_MB = 500
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

CANDIDATE_GEMINI_MODELS = [
    "gemini-flash-lite-latest",
    "gemini-3.8-flash"
]

DANGEROUS_FINAL_EXTENSIONS = {
    '.exe', '.bat', '.vbs', '.ps1', '.cmd', '.scr',
    '.js', '.vbe', '.jse', '.wsf', '.wsh', '.msc',
    '.com', '.pif', '.hta', '.dll', '.sys'
}

DISGUISE_EXTENSIONS = {
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx',
    '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.zip', '.rar',
    '.mp3', '.mp4', '.avi', '.csv', '.rtf', '.svg'
}

MEDIA_AND_ARCHIVE_EXTS = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.iso'
}

EXECUTABLE_EXTS = {
    '.exe', '.dll', '.sys', '.scr', '.bat', '.vbs',
    '.ps1', '.msi', '.js', '.elf', '.com'
}

KNOWN_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".upx0", ".upx1", ".upx2",
    "aspack", ".aspack", "adata", ".adata", "fsg", ".fsg",
    "mpress1", "mpress2", ".mpress1", ".mpress2",
    "vmp0", "vmp1", ".vmp0", ".vmp1",
    "themida", ".themida", "enigma", ".enigma",
    "nsp0", "nsp1", ".nsp0", ".nsp1",
    "packer", ".packer", "pec1", "pec2", ".pec1", ".pec2"
}

SUSPICIOUS_PE_APIS = {
    "INJECTION": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
        "NtUnmapViewOfSection", "SetThreadContext", "RtlCreateUserThread",
        "SetWindowsHookExA", "SetWindowsHookExW", "SuspendThread", "ResumeThread"
    },
    "CRYPTO_RANSOM": {
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "CryptAcquireContextW", "CryptGenRandom", "CryptExportKey", "EncryptFileA", "EncryptFileW"
    },
    "EVASION": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "VirtualProtect",
        "VirtualProtectEx", "NtQueryInformationProcess", "OutputDebugStringA",
        "OutputDebugStringW", "FindWindowA", "FindWindowW"
    },
    "PERSISTENCE": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW"
    },
    "NETWORK": {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect", "gethostbyname"
    },
    "SPYWARE": {
        "GetAsyncKeyState", "GetKeyState", "GetClipboardData", "GetForegroundWindow"
    }
}

SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(rb'powershell(?:\.exe)?\s+-(?:nop|noprofile|enc|encodedcommand|executionpolicy|w\s+hidden)', re.IGNORECASE), "PowerShell (Suspicious Arguments)"),
    (re.compile(rb'powershell(?:\.exe)?\s+(?:-[a-zA-Z]|/[a-zA-Z]|\.|\$|iex|Invoke-)', re.IGNORECASE), "PowerShell Execution"),
    (re.compile(rb'cmd(?:\.exe)?\s+/[ck]', re.IGNORECASE), "Cmd Command Execution"),
    (re.compile(rb'downloadstring\s*\(', re.IGNORECASE), "DownloadString (Web Download)"),
    (re.compile(rb'downloadfile\s*\(', re.IGNORECASE), "DownloadFile (Payload Drop)"),
    (re.compile(rb'wscript\.shell', re.IGNORECASE), "WScript.Shell"),
    (re.compile(rb'cscript(?:\.exe)?', re.IGNORECASE), "cscript Execution"),
    (re.compile(rb'reg\s+(?:add|delete|query)\s+hk(?:cu|lm)', re.IGNORECASE), "Registry Manipulation (Reg)"),
    (re.compile(rb'certutil(?:\.exe)?\s+-(?:urlcache|decode)', re.IGNORECASE), "Certutil Ingress Tool"),
    (re.compile(rb'bitsadmin(?:\.exe)?\s+/transfer', re.IGNORECASE), "Bitsadmin Download"),
    (re.compile(rb'invoke-expression', re.IGNORECASE), "Invoke-Expression"),
    (re.compile(rb'system\.net\.webclient', re.IGNORECASE), "System.Net.WebClient"),
    (re.compile(rb'invoke-webrequest', re.IGNORECASE), "Invoke-WebRequest"),
    (re.compile(rb'start-process', re.IGNORECASE), "Start-Process"),
]

URL_REGEX = re.compile(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]{8,}', re.IGNORECASE)
IP_REGEX = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
BASE64_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')


def check_file_size(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        return {"valid": False, "size_bytes": 0, "size_mb": 0, "message": "ไม่พบไฟล์ในตำแหน่งที่ระบุ"}
    try:
        file_size_bytes = os.path.getsize(file_path)
    except Exception as e:
        return {"valid": False, "size_bytes": 0, "size_mb": 0, "message": f"ไม่สามารถเข้าถึงไฟล์ได้: {str(e)}"}
    file_size_mb = file_size_bytes / (1024 * 1024)
    if file_size_bytes > MAX_FILE_SIZE_BYTES:
        return {"valid": False, "size_bytes": file_size_bytes, "size_mb": round(file_size_mb, 2), "message": f"ขนาดไฟล์ ({file_size_mb:.2f} MB) เกินขีดจำกัด {MAX_FILE_SIZE_MB} MB"}
    return {"valid": True, "size_bytes": file_size_bytes, "size_mb": round(file_size_mb, 2), "message": f"ขนาดไฟล์ปกติ ({file_size_mb:.2f} MB)"}


def calculate_sha256_stream(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_entropy(sample_bytes: bytes) -> float:
    if not sample_bytes:
        return 0.0
    counter = Counter(sample_bytes)
    total_bytes = len(sample_bytes)
    entropy = 0.0
    for count in counter.values():
        p = count / total_bytes
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def evaluate_entropy_risk(entropy: float, file_name: str) -> Dict[str, Any]:
    ext = os.path.splitext(file_name)[1].lower()
    if entropy > 7.2:
        if ext in EXECUTABLE_EXTS:
            return {"is_suspicious": True, "code": "HIGH_SUSPICIOUS", "description": "ความซับซ้อนสูง (>7.2) - สุ่มเสี่ยงโดน Pack / Obfuscate / เข้ารหัสลับ"}
        elif ext in MEDIA_AND_ARCHIVE_EXTS:
            return {"is_suspicious": False, "code": "NORMAL_MEDIA", "description": "ปกติ (ไฟล์บีบอัด หรือไฟล์สื่อมัลติมีเดียมี Entropy สูงเป็นปกติ)"}
        else:
            return {"is_suspicious": False, "code": "HIGH_GENERIC", "description": "ความซับซ้อนสูง (>7.2) - ข้อมูลบีบอัดสูง"}
    return {"is_suspicious": False, "code": "NORMAL", "description": "ปกติ (อยู่ในเกณฑ์มาตรฐาน < 7.2)"}


def analyze_pe_sections(file_bytes: bytes) -> Dict[str, Any]:
    if pefile is None:
        return {
            "is_pe": False,
            "suspicious_sections": [],
            "all_sections": [],
            "has_suspicious_sections": False,
            "has_wx_sections": False,
            "is_packed": False,
            "imphash": "",
            "dangerous_apis": [],
            "api_categories": {},
            "has_critical_apis": False,
            "error": "ไม่พบไลบรารี pefile"
        }
    try:
        pe = pefile.PE(data=file_bytes)
        suspicious_sections = []
        all_sections = []
        has_wx = False
        is_packed = False
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00').strip()
            entropy = round(section.get_entropy(), 2)
            chars = section.Characteristics
            is_write = bool(chars & 0x80000000)
            is_exec = bool(chars & 0x20000000)
            sec_wx = is_write and is_exec
            if sec_wx:
                has_wx = True
            
            is_sec_packed = sec_name.lower() in KNOWN_PACKER_SECTIONS
            if is_sec_packed:
                is_packed = True
                
            is_susp = (entropy > 7.5) or sec_wx or is_sec_packed
            sec_info = {
                "name": sec_name or "[Unnamed]",
                "entropy": entropy,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "is_suspicious": is_susp,
                "is_wx": sec_wx,
                "is_packed": is_sec_packed
            }
            all_sections.append(sec_info)
            if is_susp:
                suspicious_sections.append(sec_info)
                
        # Analyze Import Table (IAT)
        dangerous_apis = []
        api_categories = {
            "injection": [],
            "crypto_ransom": [],
            "evasion": [],
            "persistence": [],
            "network": [],
            "spyware": []
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp and imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if func_name in SUSPICIOUS_PE_APIS["INJECTION"]:
                            api_categories["injection"].append(func_name)
                            dangerous_apis.append(f"{func_name} (Code Injection / Process Hollowing)")
                        elif func_name in SUSPICIOUS_PE_APIS["CRYPTO_RANSOM"]:
                            api_categories["crypto_ransom"].append(func_name)
                            dangerous_apis.append(f"{func_name} (Ransomware / File Encryption)")
                        elif func_name in SUSPICIOUS_PE_APIS["EVASION"]:
                            api_categories["evasion"].append(func_name)
                            dangerous_apis.append(f"{func_name} (Anti-Debug / Evasion)")
                        elif func_name in SUSPICIOUS_PE_APIS["PERSISTENCE"]:
                            api_categories["persistence"].append(func_name)
                            dangerous_apis.append(f"{func_name} (System Persistence)")
                        elif func_name in SUSPICIOUS_PE_APIS["NETWORK"]:
                            api_categories["network"].append(func_name)
                            dangerous_apis.append(f"{func_name} (Outbound C2 / Dropper)")
                        elif func_name in SUSPICIOUS_PE_APIS["SPYWARE"]:
                            api_categories["spyware"].append(func_name)
                            dangerous_apis.append(f"{func_name} (Keylogger / Data Spy)")

        has_critical_apis = bool(
            api_categories["injection"] or 
            (len(api_categories["crypto_ransom"]) >= 2) or
            (len(api_categories["evasion"]) >= 2 and api_categories["network"]) or
            (api_categories["crypto_ransom"] and has_wx)
        )
        
        imphash = ""
        try:
            imphash = pe.get_imphash()
        except Exception:
            pass
            
        return {
            "is_pe": True,
            "suspicious_sections": suspicious_sections,
            "all_sections": all_sections,
            "has_suspicious_sections": len(suspicious_sections) > 0,
            "has_wx_sections": has_wx,
            "is_packed": is_packed,
            "imphash": imphash,
            "dangerous_apis": dangerous_apis,
            "api_categories": api_categories,
            "has_critical_apis": has_critical_apis,
            "error": None
        }
    except Exception:
        return {
            "is_pe": False,
            "suspicious_sections": [],
            "all_sections": [],
            "has_suspicious_sections": False,
            "has_wx_sections": False,
            "is_packed": False,
            "imphash": "",
            "dangerous_apis": [],
            "api_categories": {},
            "has_critical_apis": False,
            "error": "ไม่ใช่ไฟล์ Portable Executable (Windows Binary)"
        }


def verify_magic_bytes(header_bytes: bytes, file_name: str) -> Dict[str, Any]:
    ext = os.path.splitext(file_name)[1].lower()
    if ext in ['.exe', '.dll', '.sys', '.scr']:
        if not header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "Executable (MZ)", "actual": "Non-MZ Header", "message": f"โครงสร้าง Header ไม่ตรง: นามสกุล {ext} แต่ไม่มี MZ Signature"}
        return {"is_spoofed": False, "expected": "Executable (MZ)", "actual": "Executable (MZ)", "message": "ถูกต้อง (Valid MZ Header)"}
    elif ext in ['.jpg', '.jpeg']:
        if header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "JPEG Image", "actual": "Executable (MZ)", "message": f"🚨 ปลอมแปลงนามสกุล: ไฟล์โปรแกรม (.exe) ปลอมตัวเป็นรูปภาพ {ext}!"}
        elif not header_bytes.startswith(b'\xff\xd8\xff'):
            return {"is_spoofed": True, "expected": "JPEG Image", "actual": "Unknown", "message": "โครงสร้าง Header ไม่ตรงกับไฟล์ JPEG"}
        return {"is_spoofed": False, "expected": "JPEG Image", "actual": "JPEG Image", "message": "ถูกต้อง (Valid JPEG Header)"}
    elif ext == '.png':
        if header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "PNG Image", "actual": "Executable (MZ)", "message": "🚨 ปลอมแปลงนามสกุล: ไฟล์โปรแกรม (.exe) ปลอมตัวเป็นรูปภาพ PNG!"}
        elif not header_bytes.startswith(b'\x89PNG'):
            return {"is_spoofed": True, "expected": "PNG Image", "actual": "Unknown", "message": "โครงสร้าง Header ไม่ตรงกับไฟล์ PNG"}
        return {"is_spoofed": False, "expected": "PNG Image", "actual": "PNG Image", "message": "ถูกต้อง (Valid PNG Header)"}
    elif ext == '.pdf':
        if header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "PDF Document", "actual": "Executable (MZ)", "message": "🚨 ปลอมแปลงนามสกุล: ไฟล์โปรแกรม (.exe) ปลอมตัวเป็นเอกสาร PDF!"}
        elif not header_bytes.startswith(b'%PDF'):
            return {"is_spoofed": True, "expected": "PDF Document", "actual": "Unknown", "message": "โครงสร้าง Header ไม่ตรงกับไฟล์ PDF"}
        return {"is_spoofed": False, "expected": "PDF Document", "actual": "PDF Document", "message": "ถูกต้อง (Valid PDF Header)"}
    elif ext in ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk']:
        if header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "ZIP/Archive", "actual": "Executable (MZ)", "message": f"🚨 ปลอมแปลงนามสกุล: ไฟล์โปรแกรม (.exe) ปลอมตัวเป็นไฟล์บีบอัด/เอกสาร {ext}!"}
        elif not header_bytes.startswith(b'PK\x03\x04'):
            return {"is_spoofed": True, "expected": "ZIP/Archive", "actual": "Unknown", "message": "โครงสร้าง Header ไม่ตรงกับไฟล์ ZIP/Archive"}
        return {"is_spoofed": False, "expected": "ZIP/Archive", "actual": "ZIP/Archive", "message": "ถูกต้อง (Valid ZIP/Archive Header)"}
    elif ext in ['.mp4', '.m4v']:
        if header_bytes.startswith(b'MZ'):
            return {"is_spoofed": True, "expected": "MP4 Video", "actual": "Executable (MZ)", "message": f"🚨 ปลอมแปลงนามสกุล: ไฟล์โปรแกรม (.exe) ปลอมตัวเป็นวิดีโอ MP4!"}
        return {"is_spoofed": False, "expected": "MP4 Video", "actual": "MP4 Video", "message": "ถูกต้อง (Valid MP4 Header)"}
    return {"is_spoofed": False, "expected": "Generic", "actual": "Generic", "message": "ข้ามการตรวจ Header สำหรับนามสกุลทั่วไป"}


def check_double_extension(file_name: str) -> Dict[str, Any]:
    clean_name = os.path.basename(file_name)
    parts = [p.lower() for p in clean_name.split('.') if p]
    if len(parts) >= 3:
        inner_parts = parts[1:-1]
        final_ext = f".{parts[-1]}"
        disguised_hits = [f".{p}" for p in inner_parts if f".{p}" in DISGUISE_EXTENSIONS]
        is_dangerous_final = final_ext in DANGEROUS_FINAL_EXTENSIONS
        if disguised_hits and is_dangerous_final:
            disguised_str = disguised_hits[0]
            return {"is_double_ext": True, "final_ext": final_ext, "all_exts": [f".{p}" for p in parts[1:]], "is_dangerous": True, "ext_chain": f"{disguised_str}{final_ext}", "message": f"🚨 ตรวจพบนามสกุลซ้อนอันตราย: แอบแฝง '{disguised_str}' ก่อนนามสกุลโปรแกรม '{final_ext}'!"}
        elif disguised_hits:
            return {"is_double_ext": True, "final_ext": final_ext, "all_exts": [f".{p}" for p in parts[1:]], "is_dangerous": False, "ext_chain": "".join([f".{p}" for p in parts[1:]]), "message": f"⚠️ ตรวจพบนามสกุลซ้อน: '{''.join(disguised_hits)}'"}
    final_single_ext = f".{parts[-1]}" if len(parts) >= 2 else ""
    return {"is_double_ext": False, "final_ext": final_single_ext, "all_exts": [final_single_ext] if final_single_ext else [], "is_dangerous": False, "ext_chain": final_single_ext, "message": "นามสกุลเดี่ยวปกติ"}


def extract_and_analyze_strings(file_bytes: bytes, file_name: str, max_scan_bytes: int = 5_000_000) -> Dict[str, Any]:
    ext = os.path.splitext(file_name)[1].lower()
    is_media_file = ext in MEDIA_AND_ARCHIVE_EXTS
    data_to_scan = file_bytes[:max_scan_bytes]
    ascii_strings = re.findall(rb'[ -~]{5,}', data_to_scan)
    found_plain_cmds = set()
    found_b64_cmds = set()
    found_urls = set()
    found_ips = set()
    
    b64_candidates = BASE64_PATTERN.findall(data_to_scan)
    for b64_bytes in b64_candidates:
        try:
            decoded_bytes = base64.b64decode(b64_bytes)
            if len(decoded_bytes) >= 10:
                for pattern, cmd_name in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(decoded_bytes):
                        found_b64_cmds.add(f"{cmd_name} (ถอดรหัสจาก Base64)")
        except Exception:
            pass
            
    for s_bytes in ascii_strings:
        for pattern, cmd_name in SUSPICIOUS_CMD_PATTERNS:
            if pattern.search(s_bytes):
                found_plain_cmds.add(cmd_name)
        urls = URL_REGEX.findall(s_bytes)
        for u in urls:
            try:
                u_str = u.decode('ascii', errors='ignore').rstrip('.,;)')
                if len(u_str) > 10 and not u_str.endswith(('.w3.org', '.apple.com', '.adobe.com')):
                    found_urls.add(u_str)
            except Exception:
                pass
        ips = IP_REGEX.findall(s_bytes)
        for ip in ips:
            try:
                ip_str = ip.decode('ascii', errors='ignore')
                if not ip_str.startswith(("0.", "127.", "255.", "192.168.", "10.")):
                    found_ips.add(ip_str)
            except Exception:
                pass

    all_commands = sorted(list(found_plain_cmds | found_b64_cmds))
    if is_media_file and not found_b64_cmds and len(found_plain_cmds) <= 1:
        has_suspicious_cmds = False
        display_commands = []
    else:
        has_suspicious_cmds = len(all_commands) > 0
        display_commands = all_commands
    
    return {"found_commands": display_commands, "found_plain_cmds": sorted(list(found_plain_cmds)), "found_b64_cmds": sorted(list(found_b64_cmds)), "found_urls": sorted(list(found_urls))[:10], "found_ips": sorted(list(found_ips))[:10], "has_suspicious_cmds": has_suspicious_cmds, "has_network_indicators": (len(found_urls) > 0) or (len(found_ips) > 0), "total_ascii_strings": len(ascii_strings)}


def query_virustotal(sha256: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"available": False, "status": "NO_API_KEY", "message": "ไม่ได้ระบุ VirusTotal API Key (โหมด Offline)", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"accept": "application/json", "x-apikey": api_key.strip()}
    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {"available": True, "status": "FOUND", "message": "พบประวัติการสแกนใน VirusTotal Cloud", "malicious": stats.get('malicious', 0), "suspicious": stats.get('suspicious', 0), "harmless": stats.get('harmless', 0), "undetected": stats.get('undetected', 0)}
        elif response.status_code == 404:
            return {"available": True, "status": "NOT_FOUND", "message": "ไม่พบประวัติในระบบ VirusTotal (เป็นไฟล์ใหม่หรือไฟล์ส่วนตัว)", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        else:
            return {"available": False, "status": f"ERROR_{response.status_code}", "message": f"VirusTotal Error (Code: {response.status_code})", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    except Exception as e:
        return {"available": False, "status": "EXCEPTION", "message": f"ไม่สามารถเชื่อมต่อ VirusTotal: {str(e)}", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}


def call_gemini_api(api_key: str, payload: dict) -> str:
    if not api_key:
        return ""
    cleaned_key = api_key.strip()
    headers = {"Content-Type": "application/json"}
    last_error_code = None
    last_error_msg = ""

    for model_name in CANDIDATE_GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={cleaned_key}"
        for attempt in range(2):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get('candidates', [])
                    if candidates and 'content' in candidates[0]:
                        parts = candidates[0]['content'].get('parts', [])
                        if parts and 'text' in parts[0]:
                            return parts[0]['text']
                    return "ℹ️ Gemini ตอบกลับแต่ไม่พบข้อความเนื้อหา"
                last_error_code = response.status_code
                if response.status_code in [503, 429]:
                    time.sleep(1)
                    continue
                elif response.status_code == 400:
                    last_error_msg = "API Key ไม่ถูกต้อง (Code 400)"
                    break
                else:
                    last_error_msg = f"HTTP {response.status_code}: {response.text[:150]}"
                    break
            except Exception as e:
                last_error_msg = str(e)
                time.sleep(1)
                
    if last_error_code == 503:
        return "⚠️ เซิร์ฟเวอร์ Google Gemini กำลังมีผู้ใช้งานหนาแน่นชั่วคราว (503) กรุณากดส่งคำถามอีกครั้งในอีกสักครู่ครับ"
    elif last_error_code == 400:
        return "⚠️ ตรวจสอบพบว่า Gemini API Key ไม่ถูกต้อง กรุณาตรวจสอบ API Key ในเมนู '⚙️ ตั้งค่า API Keys'"
    else:
        return f"⚠️ ไม่สามารถติดต่อ Gemini AI ได้: {last_error_msg or 'กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ต'}"


def generate_ai_analysis(scan_data: Dict[str, Any], api_key: Optional[str] = None, lang: str = "th") -> Dict[str, str]:
    is_en = (lang == "en")
    threat_reasons = []
    if scan_data.get("yara_result", {}).get("matched"):
        matched_names = [m["rule"] for m in scan_data["yara_result"]["matches"]]
        if is_en:
            threat_reasons.append(f"matched YARA malware signatures ({', '.join(matched_names)})")
        else:
            threat_reasons.append(f"ตรวจพบลายนิ้วมือมัลแวร์ตรงตามกฎ YARA ({', '.join(matched_names)})")
    if scan_data["magic_bytes"]["is_spoofed"]:
        threat_reasons.append("critical file extension spoofing detected" if is_en else "ตรวจพบการปลอมแปลงนามสกุลไฟล์อย่างร้ายแรง")
    if scan_data["double_ext"]["is_dangerous"]:
        threat_reasons.append("dangerous double extension ending with executable" if is_en else "ตรวจพบนามสกุลซ้อนอันตรายที่ลงท้ายด้วย Executable")
    if scan_data["strings_analysis"]["has_suspicious_cmds"]:
        threat_reasons.append(f"embedded suspicious system commands ({', '.join(scan_data['strings_analysis']['found_commands'])})" if is_en else f"พบคำสั่งระบบอันตรายแอบแฝง ({', '.join(scan_data['strings_analysis']['found_commands'])})")
    if scan_data.get("pe_analysis", {}).get("has_critical_apis"):
        api_names = scan_data["pe_analysis"].get("dangerous_apis", [])[:2]
        threat_reasons.append(f"dangerous Win32 APIs ({', '.join(api_names)})" if is_en else f"ตรวจพบการเรียกใช้ Windows APIs อันตราย ({', '.join(api_names)})")
    if scan_data.get("pe_analysis", {}).get("has_wx_sections"):
        threat_reasons.append("suspicious WX memory section" if is_en else "ตรวจพบ Section สิทธิ์ WX (Write+Execute Shellcode)")
    if scan_data.get("vt_result", {}).get("malicious", 0) > 0:
        threat_reasons.append(f"flagged by {scan_data['vt_result']['malicious']} security vendors on VirusTotal" if is_en else f"ตรวจพบเป็นมัลแวร์โดย Antivirus บน VirusTotal จำนวน {scan_data['vt_result']['malicious']} ค่าย")

    if scan_data["overall_risk"] == "SAFE":
        if scan_data.get("is_digitally_signed"):
            local_summary = (
                "✅ Clean & Verified: Digitally signed by an authentic trusted publisher. No malware threats detected."
                if is_en else
                "✅ ปลอดภัยและมีลายเซ็นรับรอง (Signed & Verified): โปรแกรมมีลายเซ็นดิจิทัลแท้จากผู้พัฒนา ไม่พบรหัสอันตรายหรือพฤติกรรมมัลแวร์"
            )
        else:
            local_summary = (
                "✅ Clean & Safe: Valid magic headers, no matching YARA signatures, and no malicious patterns detected."
                if is_en else
                "✅ ไม่พบความผิดปกติหรือภัยคุกคาม โครงสร้างไฟล์ถูกต้องตรงตามนามสกุล ผ่านการตรวจ YARA Signatures และไม่พบคำสั่งอันตรายแอบแฝง"
            )
    elif scan_data["overall_risk"] == "DANGER":
        if is_en:
            local_summary = f"🚨 High Security Risk! Detected: {' and '.join(threat_reasons) if threat_reasons else 'Critical threat patterns'}. Quarantining is strongly advised."
        else:
            local_summary = f"🚨 ไฟล์นี้มีความเสี่ยงอันตรายสูง! ตรวจพบ: {' และ '.join(threat_reasons) if threat_reasons else 'รูปแบบภัยคุกคามระดับสูง'} แนะนำให้กักกันไฟล์เพื่อความปลอดภัย"
    else:  # WARNING
        if scan_data["double_ext"]["is_double_ext"]:
            local_summary = (
                f"⚠️ Double file extension detected ({scan_data['double_ext']['ext_chain']}). Verify file origin."
                if is_en else
                f"⚠️ ตรวจพบนามสกุลไฟล์ซ้อน ({scan_data['double_ext']['ext_chain']}) แนะนำให้ตรวจสอบแหล่งที่มาของไฟล์ก่อนเปิดใช้งาน"
            )
        else:
            local_summary = (
                "⚠️ Warning: Elevated entropy or suspicious heuristics detected. Verify file authenticity before execution."
                if is_en else
                "⚠️ ควรระมัดระวังเป็นพิเศษ: ตรวจพบลักษณะที่อาจเป็นข้อควรระวัง (ความซับซ้อนของไฟล์สูงหรือมีพฤติกรรมสุ่มเสี่ยง) แนะนำให้ตรวจสอบที่มาก่อนเปิดใช้งาน"
            )

    if not api_key:
        fallback_details = (
            "ℹ️ Local Scanner Mode: Provide a Gemini API Key in '⚙️ Settings' for in-depth AI security analysis."
            if is_en else
            "ℹ️ โหมด Local Scanner: ป้อน Gemini API Key ในเมนูตั้งค่าด้านบนเพื่อเปิดใช้งานบทวิเคราะห์เชิงลึกและคำแนะนำความปลอดภัยเพิ่มเติมจาก AI"
        )
        return {"summary": local_summary, "details": fallback_details, "is_ai_generated": False}

    pe_sections_str = ", ".join([f"{s['name']} (Entropy: {s['entropy']})" for s in scan_data['pe_analysis']['suspicious_sections']]) if scan_data['pe_analysis']['suspicious_sections'] else "None"
    cmd_str = ", ".join(scan_data['strings_analysis']['found_commands']) if scan_data['strings_analysis']['found_commands'] else "None"
    vt_str = f"Malicious: {scan_data.get('vt_result', {}).get('malicious', 0)}, Suspicious: {scan_data.get('vt_result', {}).get('suspicious', 0)}, Clean: {scan_data.get('vt_result', {}).get('harmless', 0) + scan_data.get('vt_result', {}).get('undetected', 0)}"
    yara_str = scan_data.get('yara_result', {}).get('summary', 'None' if is_en else 'ไม่มี')

    lang_instructions = """
    CRITICAL LANGUAGE REQUIREMENT:
    Respond ENTIRELY in fluent, professional ENGLISH.
    Format your answer into 2 sections separated by '---DETAILS---':
    Part 1: Quick executive security summary in 2-3 sentences.
    ---DETAILS---
    Part 2: Technical bulleted observations and recommended actions.
    """ if is_en else """
    ข้อกำหนดด้านภาษา:
    ตอบเป็นภาษาไทยทั้งหมดอย่างกระชับ เข้าใจง่าย ตรงประเด็น
    กรุณาจัดรูปแบบคำตอบแบ่งเป็น 2 ส่วนคั่นด้วย '---DETAILS---':
    ส่วนที่ 1: สรุปผลความปลอดภัยด่วน 2-3 ประโยคภาษาไทยที่คนทั่วไปอ่านเข้าใจทันที
    ---DETAILS---
    ส่วนที่ 2: คำแนะนำเชิงเทคนิคและข้อควรปฏิบัติภาษาไทยแบบเป็นข้อๆ ชัดเจน
    """

    sig_status = "Valid Authenticode (Verified / Signed Binary)" if scan_data.get("is_digitally_signed") else "Unsigned / No Signature"
    prompt = f"""
    You are an expert Cybersecurity and Malware Analysis Specialist.
    Analyze the following security audit data accurately:

    Scan Findings:
    - Target: {scan_data['file_name']} (Size: {scan_data['file_size_mb']:.2f} MB)
    - Digital Signature: {sig_status}
    - YARA Signatures: {yara_str}
    - Magic Bytes: {scan_data['magic_bytes']['message']} (Spoofed: {scan_data['magic_bytes']['is_spoofed']})
    - Double Extension: {scan_data['double_ext']['message']}
    - Shannon Entropy: {scan_data['entropy']} / 8.0 ({scan_data['entropy_risk']['description']})
    - PE Section Entropy > 7.5: {pe_sections_str}
    - Extracted Suspicious Commands: {cmd_str}
    - VirusTotal Result: {vt_str}
    - Overall Risk Level: {scan_data['overall_risk']}

    Guidelines:
    1. If matched by YARA (e.g. Ransomware, InfoStealer, Mimikatz), clearly explain the threat behaviors and risks.
    2. If it is a legitimate installer with clean metrics and no hidden shell code, explain that it appears benign.
    3. If spoofing or malicious command chains are found, highlight severe danger.
    4. If the binary is digitally signed by a valid vendor and has clean metrics, assure the user it is an official verified program.

    {lang_instructions}
    """

    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    ai_raw = call_gemini_api(api_key, payload)

    if "---DETAILS---" in ai_raw:
        parts = ai_raw.split("---DETAILS---")
        return {"summary": parts[0].strip(), "details": parts[1].strip(), "is_ai_generated": True}
    elif ai_raw and not ai_raw.startswith("⚠️"):
        lines = [l.strip() for l in ai_raw.split('\n') if l.strip()]
        return {"summary": " ".join(lines[:2]) if len(lines) >= 2 else ai_raw, "details": ai_raw, "is_ai_generated": True}
    else:
        err_msg = ("⚠️ Unable to connect to Gemini AI" if is_en else "⚠️ ไม่สามารถเชื่อมต่อกับ Gemini AI ได้")
        return {"summary": local_summary, "details": ai_raw or err_msg, "is_ai_generated": False}


def ask_gemini_chat(file_context: Dict[str, Any], chat_history: List[Dict[str, str]], user_question: str, api_key: str, lang: str = "auto") -> str:
    if not api_key:
        if lang == "en":
            return "⚠️ Please provide a Gemini API Key in '⚙️ Settings' to use the AI Chatbot."
        return "⚠️ กรุณาระบุ Gemini API Key ในเมนู '⚙️ ตั้งค่า' เพื่อใช้งาน AI Chatbot"

    pe_sec_str = ", ".join([f"{s['name']} ({s['entropy']})" for s in file_context.get('pe_analysis', {}).get('suspicious_sections', [])]) or "None"
    cmds_str = ", ".join(file_context.get('strings_analysis', {}).get('found_commands', [])) or "None"
    yara_str = file_context.get('yara_result', {}).get('summary', 'None')
    
    system_ctx = f"""
    You are an expert Cybersecurity AI Assistant.
    You are analyzing and discussing a scanned file or system audit:
    - Target/File Name: {file_context.get('file_name')} ({file_context.get('file_size_mb', 0):.2f} MB)
    - Overall Risk Level: {file_context.get('overall_risk')}
    - YARA Signatures: {yara_str}
    - Suspicious Commands: {cmds_str}
    - Suspicious PE Sections: {pe_sec_str}
    - Context Summary: {file_context.get('ai_summary', '')}

    CRITICAL LANGUAGE INSTRUCTION:
    - Respond in the EXACT SAME LANGUAGE as the user's latest question.
    - If the user asks in English, reply entirely in fluent, professional English.
    - If the user asks in Thai, reply entirely in clear, friendly Thai.
    - If the user's language is ambiguous, follow the UI language preference: '{lang if lang in ['th', 'en'] else 'Thai'}'.
    - Keep your answer concise, accurate, actionable, and focused on security best practices.
    """

    full_prompt = system_ctx + "\nChat History:\n"
    for msg in chat_history:
        full_prompt += f"{msg['role'].upper()}: {msg['text']}\n"
    full_prompt += f"USER: {user_question}\nASSISTANT:"

    payload = {"contents": [{"parts": [{"text": full_prompt}]}]}
    return call_gemini_api(api_key, payload)


def scan_file(file_path: str, vt_api_key: Optional[str] = None, gemini_api_key: Optional[str] = None, auto_quarantine: bool = False, lang: str = "th") -> Dict[str, Any]:
    size_check = check_file_size(file_path)
    if not size_check["valid"]:
        return {"success": False, "error": size_check["message"], "file_name": os.path.basename(file_path), "file_path": file_path, "file_size_mb": size_check["size_mb"]}
        
    file_name = os.path.basename(file_path)
    sha256 = calculate_sha256_stream(file_path)
    
    with open(file_path, "rb") as f:
        header_sample = f.read(4096)
        f.seek(0)
        scan_sample = f.read(10 * 1024 * 1024)
        
    entropy = calculate_entropy(scan_sample)
    entropy_risk = evaluate_entropy_risk(entropy, file_name)
    pe_analysis = analyze_pe_sections(scan_sample)
    magic_bytes = verify_magic_bytes(header_sample, file_name)
    double_ext = check_double_extension(file_name)
    strings_analysis = extract_and_analyze_strings(scan_sample, file_name)
    
    vt_result = query_virustotal(sha256, vt_api_key) if vt_api_key else {"available": False, "status": "OFFLINE", "message": "ไม่ได้ระบุ API Key (Local Scan)", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    
    # Digital Signature Verification (WinVerifyTrust)
    is_digitally_signed = verify_digital_signature(file_path)

    # YARA Signatures Scan
    yara_result = run_yara_scan(file_path)
    yara_has_danger = yara_result.get("matched", False) and any(m.get("severity") == "DANGER" for m in yara_result.get("matches", []))
    yara_has_warning = yara_result.get("matched", False) and not yara_has_danger

    if is_digitally_signed:
        # Legitimate signed binaries: avoid false positives from benign system APIs or packer heuristics
        is_danger = (
            yara_has_danger or
            magic_bytes["is_spoofed"] or
            double_ext["is_dangerous"] or
            (vt_result.get("malicious", 0) >= 3)
        )
        # For signed binaries: real malware warnings, VT detections, or packed/obfuscated code with suspicious commands
        is_warning = (
            not is_danger and (
                (yara_has_warning and not any("Generic_Process_Injection" in m.get("rule", "") for m in yara_result.get("matches", []))) or
                (vt_result.get("malicious", 0) in (1, 2)) or
                (vt_result.get("suspicious", 0) > 0) or
                double_ext["is_double_ext"] or
                (entropy_risk["is_suspicious"] and (strings_analysis["has_suspicious_cmds"] or pe_analysis.get("has_wx_sections", False))) or
                (entropy_risk["is_suspicious"] and not yara_result.get("available", False))
            )
        )
    else:
        is_danger = (
            yara_has_danger or
            magic_bytes["is_spoofed"] or
            double_ext["is_dangerous"] or
            strings_analysis["has_suspicious_cmds"] or
            pe_analysis.get("has_critical_apis", False) or
            pe_analysis.get("has_wx_sections", False) or
            (vt_result.get("malicious", 0) > 0)
        )
        is_warning = (
            not is_danger and (
                yara_has_warning or
                entropy_risk["is_suspicious"] or
                pe_analysis["has_suspicious_sections"] or
                len(pe_analysis.get("dangerous_apis", [])) > 0 or
                pe_analysis.get("is_packed", False) or
                strings_analysis["has_network_indicators"] or
                double_ext["is_double_ext"] or
                (vt_result.get("suspicious", 0) > 0)
            )
        )

    if is_danger:
        overall_risk = "DANGER"
        risk_color = "#ef4444"
        risk_badge_bg = "#fee2e2"
        risk_badge_border = "#f87171"
        risk_badge_text = "#991b1b"
        risk_label = "🚨 Critical Danger (Threat Detected)" if lang == "en" else "🚨 อันตรายร้ายแรง (Danger / High Threat)"
    elif is_warning:
        overall_risk = "WARNING"
        risk_color = "#f59e0b"
        risk_badge_bg = "#fef3c7"
        risk_badge_border = "#fbbf24"
        risk_badge_text = "#92400e"
        risk_label = "⚠️ Suspicious / Warning" if lang == "en" else "⚠️ ควรระมัดระวัง (Suspicious / Warning)"
    else:
        overall_risk = "SAFE"
        risk_color = "#22c55e"
        risk_badge_bg = "#dcfce7"
        risk_badge_border = "#4ade80"
        risk_badge_text = "#166534"
        risk_label = "🟢 Clean & Safe" if lang == "en" else "🟢 ปลอดภัย (Clean / Safe)"

    # Auto-quarantine if enabled and dangerous
    quarantine_info = None
    if is_danger and auto_quarantine and os.path.exists(file_path):
        q_reason = f"Detected YARA threat: {yara_result['matches'][0]['rule']}" if yara_result.get("matched") and yara_result.get("matches") else "Critical malware threat detected"
        quarantine_info = quarantine_file(file_path, q_reason)

    prelim_data = {
        "file_name": file_name,
        "file_size_mb": size_check["size_mb"],
        "entropy": entropy,
        "entropy_risk": entropy_risk,
        "pe_analysis": pe_analysis,
        "magic_bytes": magic_bytes,
        "double_ext": double_ext,
        "strings_analysis": strings_analysis,
        "yara_result": yara_result,
        "vt_result": vt_result,
        "is_digitally_signed": is_digitally_signed,
        "overall_risk": overall_risk
    }

    ai_result = generate_ai_analysis(prelim_data, gemini_api_key, lang=lang)
        
    return {
        "success": True,
        "file_name": file_name,
        "file_path": file_path,
        "file_size_mb": size_check["size_mb"],
        "file_size_bytes": size_check["size_bytes"],
        "sha256": sha256,
        "entropy": entropy,
        "entropy_risk": entropy_risk,
        "pe_analysis": pe_analysis,
        "magic_bytes": magic_bytes,
        "double_ext": double_ext,
        "strings_analysis": strings_analysis,
        "yara_result": yara_result,
        "vt_result": vt_result,
        "is_digitally_signed": is_digitally_signed,
        "overall_risk": overall_risk,
        "risk_color": risk_color,
        "risk_badge_bg": risk_badge_bg,
        "risk_badge_border": risk_badge_border,
        "risk_badge_text": risk_badge_text,
        "risk_label": risk_label,
        "ai_summary": ai_result["summary"],
        "ai_details": ai_result["details"],
        "is_ai_generated": ai_result["is_ai_generated"],
        "quarantine_info": quarantine_info
    }
