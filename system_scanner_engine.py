import os
import sys
import winreg
import psutil
import ctypes
from ctypes import wintypes
import uuid
from typing import Dict, Any, List, Optional, Callable

from quarantine_manager import quarantine_file, kill_and_quarantine_process
from yara_engine import run_yara_scan

# ==========================================
# 1. Native Windows Authenticode Signature Verification (WinVerifyTrust)
# ==========================================

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p)
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p)
    ]

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000080

_ACTION_GENERIC_VERIFY_V2_UUID = uuid.UUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}')
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID.from_buffer_copy(_ACTION_GENERIC_VERIFY_V2_UUID.bytes_le)


def verify_digital_signature(file_path: str) -> bool:
    """
    Verifies the Authenticode digital signature of a binary using native Windows WinVerifyTrust API.
    Returns True if the file has a valid digital signature from a trusted vendor.
    """
    if not file_path or not os.path.exists(file_path):
        return False
    try:
        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(GUID),
            ctypes.POINTER(WINTRUST_DATA)
        ]
        wintrust.WinVerifyTrust.restype = wintypes.LONG

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = WTD_STATEACTION_IGNORE
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
        trust_data.dwUIContext = 0
        trust_data.pSignatureSettings = None

        status = wintrust.WinVerifyTrust(
            wintypes.HWND(0),
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data)
        )
        return status == 0
    except Exception:
        return False


# ==========================================
# 2. 3-Dimensional Whitelist Profiles & Exclusions
# ==========================================

SUSPICIOUS_PROCESS_NAMES = {
    "svch0st.exe", "scvhost.exe", "csrsss.exe", "lsasss.exe",
    "servicese.exe", "winl0gon.exe", "smsss.exe", "taskmngr.exe",
    "spoolsvv.exe", "explorerr.exe"
}

SUSPICIOUS_SCRIPT_EXTS = {
    ".bat", ".vbs", ".ps1", ".cmd", ".scr", ".hta", ".js", ".vbe", ".wsf"
}

SYSTEM_CORE_NAMES = {
    "system idle process", "system", "registry", "memcompression",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe",
    "ctfmon.exe", "conhost.exe", "fontdrvhost.exe", "spoolsv.exe", "runtimebroker.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "nissrv.exe", "smartscreen.exe", "dllhost.exe", "wudfhost.exe",
    "dashost.exe", "searchindexer.exe", "audiodg.exe", "wlanext.exe", "wmiprvse.exe"
}

KNOWN_TRUSTED_APPNAMES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "antigravity.exe", "code.exe", "devenv.exe", "pycharm64.exe", "idea64.exe",
    "git.exe", "node.exe", "python.exe", "pythonw.exe", "powershell.exe", "pwsh.exe",
    "cmd.exe", "slack.exe", "discord.exe", "teams.exe", "spotify.exe", "steam.exe",
    "malwarescanner.exe"
}


def is_in_temp_folder(path: str) -> bool:
    """Checks if a given path is located in a temporary directory (%TEMP%, Temp, etc.)."""
    if not path:
        return False
    lower_path = path.lower()
    temp_dir = os.environ.get("TEMP", "").lower()
    if temp_dir and temp_dir in lower_path:
        return True
    if "\\temp\\" in lower_path or "\\appdata\\local\\temp" in lower_path or "\\windows\\temp" in lower_path:
        return True
    return False


def is_self_or_project_path(path: str) -> bool:
    """Checks if a given path belongs to this antivirus project or development tools."""
    if not path:
        return False
    lp = path.lower().replace("/", "\\")
    indicators = [
        "project antivirus", "my antivirus desktop app", "my antivirus web app",
        "malware_scanner_app", "safe_test_lab", "antigravity"
    ]
    if any(ind in lp for ind in indicators):
        return True
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__)).lower().replace("/", "\\")
        if app_dir and app_dir in lp:
            return True
    except Exception:
        pass
    return False


def evaluate_process_trust(pid: int, name: str, exe_path: str, cmdline: str) -> tuple[bool, Optional[str]]:
    """
    Evaluates whether a running process is trusted using the 3D Whitelist:
    - Dimension 1: Process Profile & Known Binaries
    - Dimension 2: Path Integrity (Anti-Masquerading)
    - Dimension 3: Native Digital Signature Verification
    Returns (is_trusted, threat_reason).
    """
    lower_name = (name or "").lower()
    lower_path = (exe_path or "").lower().replace("/", "\\")

    # 1. Windows Kernel pseudo-processes
    if pid <= 4 or lower_name in {"system idle process", "system", "registry", "memcompression"} or not name:
        return True, None

    # 2. Self and Project exclusions (Scanner Scans Scanner prevention)
    if pid == os.getpid():
        return True, None
    if is_self_or_project_path(exe_path) or is_self_or_project_path(cmdline):
        return True, None

    # 3. System Core Process Check & Anti-Masquerading
    if lower_name in SYSTEM_CORE_NAMES:
        if not exe_path:
            # Protected Windows System Service (Access Denied)
            return True, None
        is_legit = (
            lower_path.startswith("c:\\windows\\system32\\") or
            lower_path.startswith("c:\\windows\\syswow64\\") or
            lower_path == "c:\\windows\\explorer.exe" or
            "\\windows defender\\" in lower_path or
            "\\windows\\systemapps\\" in lower_path or
            lower_path.startswith("c:\\windows\\")
        )
        if is_legit:
            return True, None
        else:
            return False, f"ตรวจพบการปลอมแปลงชื่อโปรเซสของระบบ (Masquerading): '{name}' ทำงานจากตำแหน่งผิดปกติ '{exe_path}'"

    # 4. Standard Windows & WindowsApps directories
    if lower_path.startswith("c:\\windows\\") or lower_path.startswith("c:\\program files\\windowsapps\\"):
        if lower_name not in SUSPICIOUS_PROCESS_NAMES and not is_in_temp_folder(exe_path):
            return True, None

    # 5. Native Windows Authenticode Digital Signature Verification
    if exe_path and os.path.exists(exe_path):
        if verify_digital_signature(exe_path):
            return True, None

    # 6. Known Trusted Applications installed in standard directories
    if lower_name in KNOWN_TRUSTED_APPNAMES:
        if not is_in_temp_folder(exe_path):
            legit_prefixes = [
                "c:\\program files",
                "c:\\program files (x86)",
                os.environ.get("LOCALAPPDATA", "").lower() + "\\programs",
                "c:\\windows"
            ]
            if any(lower_path.startswith(p) for p in legit_prefixes if p):
                return True, None

    return False, None


# ==========================================
# 3. Core Scanning Engines
# ==========================================

def scan_running_processes() -> Dict[str, Any]:
    """Inspects all currently running processes in Windows with 3D Whitelist safety."""
    total_processes = 0
    suspicious_processes = []
    normal_process_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_info']):
        try:
            total_processes += 1
            info = proc.info
            name = info.get('name') or ""
            exe_path = info.get('exe') or ""
            cmdline = " ".join(info.get('cmdline') or [])
            pid = info.get('pid')

            is_trusted, threat_reason = evaluate_process_trust(pid, name, exe_path, cmdline)
            if is_trusted:
                normal_process_count += 1
                continue

            reasons = []
            is_suspicious = False
            risk_level = "INFO"

            # Check masquerading or core threat detected in whitelist evaluation
            if threat_reason:
                is_suspicious = True
                risk_level = "DANGER"
                reasons.append(threat_reason)

            # Check typosquatting system names
            if name.lower() in SUSPICIOUS_PROCESS_NAMES:
                is_suspicious = True
                risk_level = "DANGER"
                reasons.append(f"ชื่อโปรเซสเลียนแบบระบบปฏิบัติการ: '{name}'")

            # Check if running from Temp folder
            if exe_path and is_in_temp_folder(exe_path):
                is_suspicious = True
                if risk_level != "DANGER":
                    risk_level = "WARNING"
                reasons.append(f"โปรแกรมกำลังรันจากโฟลเดอร์ชั่วคราว (Temp): '{exe_path}'")

            # Check suspicious hidden PowerShell commands
            lower_cmd = cmdline.lower()
            if "powershell" in lower_cmd and ("-w hidden" in lower_cmd or "-windowstyle hidden" in lower_cmd or "-enc " in lower_cmd or "downloadstring" in lower_cmd):
                is_suspicious = True
                risk_level = "DANGER"
                reasons.append(f"ตรวจพบคำสั่ง PowerShell แอบแฝง/ซ่อนหน้าต่าง: '{cmdline[:120]}...'")
            elif "wscript.exe" in lower_cmd or "cscript.exe" in lower_cmd:
                if any(ext in lower_cmd for ext in [".vbs", ".js", ".hta"]):
                    is_suspicious = True
                    risk_level = "WARNING"
                    reasons.append(f"ตรวจพบสคริปต์ทำงานอยู่เบื้องหลัง: '{cmdline[:120]}...'")

            # YARA signature scan for untrusted executables
            if exe_path and os.path.exists(exe_path) and not exe_path.lower().startswith("c:\\windows\\system32"):
                try:
                    yara_res = run_yara_scan(exe_path)
                    if yara_res.get("matched"):
                        rule_name = yara_res["matches"][0]["rule"]
                        is_suspicious = True
                        risk_level = "DANGER"
                        reasons.append(f"ตรวจพบลายเซ็นมัลแวร์ YARA: '{rule_name}'")
                except Exception:
                    pass

            if is_suspicious:
                suspicious_processes.append({
                    "pid": pid,
                    "name": name,
                    "path": exe_path or "[Unknown Path]",
                    "cmdline": cmdline[:200],
                    "risk_level": risk_level,
                    "reasons": reasons
                })
            else:
                normal_process_count += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return {
        "total_scanned": total_processes,
        "suspicious_count": len(suspicious_processes),
        "suspicious_list": suspicious_processes,
        "clean_count": normal_process_count
    }


def scan_startup_programs() -> Dict[str, Any]:
    """Scans Windows Registry Run keys and Startup folder for autorun items with digital signature awareness."""
    startup_items = []
    suspicious_startup = []

    reg_locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    ]

    for root_key, subkey_path, label in reg_locations:
        try:
            with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                num_values = winreg.QueryInfoKey(key)[1]
                for i in range(num_values):
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        val_str = str(val_data).strip()

                        is_suspicious = False
                        risk_level = "INFO"
                        reasons = []

                        # Clean command line to isolate executable path if present
                        exe_candidate = val_str.strip('"').split('"')[0].strip()
                        if exe_candidate.endswith(".exe") and os.path.exists(exe_candidate):
                            if verify_digital_signature(exe_candidate):
                                # Legitimate signed software autorun (e.g. Discord, Spotify, Steam)
                                item_data = {
                                    "name": val_name or "[Default]",
                                    "command": val_str,
                                    "location": label,
                                    "is_suspicious": False,
                                    "risk_level": "INFO",
                                    "reasons": ["โปรแกรมมีลายเซ็นดิจิทัลรับรองถูกต้อง (Signed Binary)"]
                                }
                                startup_items.append(item_data)
                                continue

                        if is_in_temp_folder(val_str):
                            is_suspicious = True
                            risk_level = "WARNING"
                            reasons.append("โปรแกรมตั้งค่าเปิดอัตโนมัติจากโฟลเดอร์ชั่วคราว (Temp)")

                        lower_val = val_str.lower()
                        if any(s in lower_val for s in ["powershell", "cmd.exe", "wscript", "cscript", ".vbs", ".bat", ".ps1"]):
                            if "-w hidden" in lower_val or "-enc" in lower_val or is_in_temp_folder(val_str):
                                is_suspicious = True
                                risk_level = "DANGER"
                                reasons.append("ตรวจพบสคริปต์คำสั่งเปิดอัตโนมัติพร้อมเริ่มระบบ")

                        item_data = {
                            "name": val_name or "[Default]",
                            "command": val_str,
                            "location": label,
                            "is_suspicious": is_suspicious,
                            "risk_level": risk_level,
                            "reasons": reasons
                        }
                        startup_items.append(item_data)
                        if is_suspicious:
                            suspicious_startup.append(item_data)

                    except Exception:
                        continue
        except Exception:
            continue

    startup_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup"
    )
    if os.path.exists(startup_dir):
        try:
            for fname in os.listdir(startup_dir):
                fpath = os.path.join(startup_dir, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Check if signed exe in Startup
                if ext == ".exe" and verify_digital_signature(fpath):
                    item_data = {
                        "name": fname,
                        "command": fpath,
                        "location": "Startup Folder",
                        "is_suspicious": False,
                        "risk_level": "INFO",
                        "reasons": ["โปรแกรมมีลายเซ็นดิจิทัลรับรองถูกต้อง"]
                    }
                    startup_items.append(item_data)
                    continue

                is_suspicious = ext in SUSPICIOUS_SCRIPT_EXTS or ext == ".exe"
                reasons = []
                risk_level = "INFO"
                if is_suspicious:
                    risk_level = "WARNING"
                    reasons.append(f"พบไฟล์ {ext} ในโฟลเดอร์ Startup อัตโนมัติ")

                item_data = {
                    "name": fname,
                    "command": fpath,
                    "location": "Startup Folder",
                    "is_suspicious": is_suspicious,
                    "risk_level": risk_level,
                    "reasons": reasons
                }
                startup_items.append(item_data)
                if is_suspicious:
                    suspicious_startup.append(item_data)
        except Exception:
            pass

    return {
        "total_startup_items": len(startup_items),
        "suspicious_count": len(suspicious_startup),
        "suspicious_list": suspicious_startup,
        "all_items": startup_items
    }


def scan_critical_temp_folders(limit: int = 150) -> Dict[str, Any]:
    r"""
    Scans critical strategic directories (%TEMP%, AppData\Local\Temp) for executables and scripts.
    """
    temp_dirs = [
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")
    ]

    scanned_files = 0
    suspicious_files = []

    target_extensions = {".exe", ".bat", ".vbs", ".ps1", ".cmd", ".scr", ".js", ".hta", ".dll"}

    for tdir in set(temp_dirs):
        if not tdir or not os.path.exists(tdir):
            continue
        try:
            for root, _, files in os.walk(tdir):
                for f in files:
                    scanned_files += 1
                    if scanned_files > limit:
                        break
                    fpath = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()

                    if ext in target_extensions:
                        try:
                            # Skip signed binaries from temporary install packages
                            if ext == ".exe" and verify_digital_signature(fpath):
                                continue

                            fsize_mb = os.path.getsize(fpath) / (1024 * 1024)
                            suspicious_files.append({
                                "name": f,
                                "path": fpath,
                                "size_mb": round(fsize_mb, 2),
                                "extension": ext,
                                "risk_level": "WARNING" if ext != ".exe" else "INFO",
                                "reason": f"พบไฟล์ {ext} พักอยู่ในโฟลเดอร์ Temp"
                            })
                        except Exception:
                            continue
                if scanned_files > limit:
                    break
        except Exception:
            continue

    return {
        "total_temp_scanned": scanned_files,
        "suspicious_count": len(suspicious_files),
        "suspicious_files": suspicious_files[:20]
    }


def scan_network_connections() -> Dict[str, Any]:
    """Inspects active external network connections created by running processes."""
    total_connections = 0
    suspicious_connections = []

    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                total_connections += 1
                r_ip, r_port = conn.raddr.ip, conn.raddr.port

                uncommon_ports = {4444, 5555, 6666, 6667, 1337, 31337, 8888, 9999}

                proc_name = "[Unknown]"
                exe_path = ""
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                        exe_path = p.exe()
                    except Exception:
                        pass

                # If signed or legitimate browser/dev tool, normal port connection is safe
                if exe_path and verify_digital_signature(exe_path) and r_port not in uncommon_ports:
                    continue

                if r_port in uncommon_ports or (proc_name.lower() in ["powershell.exe", "cmd.exe", "wscript.exe"]):
                    suspicious_connections.append({
                        "pid": conn.pid,
                        "process": proc_name,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "status": conn.status,
                        "risk_level": "WARNING",
                        "reason": f"การเชื่อมต่อไปยังพอร์ต {r_port} หรือโปรเซสสคริปต์เชื่อมต่อเน็ต"
                    })
    except Exception:
        pass

    return {
        "total_connections": total_connections,
        "suspicious_count": len(suspicious_connections),
        "suspicious_list": suspicious_connections
    }


def run_full_system_scan(progress_callback: Optional[Callable[[str, float], None]] = None, auto_quarantine: bool = False) -> Dict[str, Any]:
    """
    Comprehensive Windows System Security Audit pipeline.
    Safety First: Strictly audits and reports system health. Never automatically terminates
    running processes during a scan without explicit user action in GUI.
    """
    findings = []
    score = 100
    auto_actions_taken = []

    # 1. Process Scan (25%)
    if progress_callback:
        progress_callback("กำลังตรวจสอบ Running Processes & Memory (3D Whitelist)...", 0.25)
    proc_res = scan_running_processes()

    for p in proc_res["suspicious_list"]:
        if p["risk_level"] == "DANGER":
            score -= 20
        else:
            score -= 8

        findings.append({
            "category": "⚙️ Running Process",
            "title": f"โปรเซส: {p['name']} (PID: {p['pid']})",
            "detail": " • ".join(p["reasons"]),
            "risk_level": p["risk_level"],
            "path": p["path"]
        })

    # 2. Startup Programs (50%)
    if progress_callback:
        progress_callback("กำลังตรวจสอบ Windows Registry Startup & Autorun...", 0.50)
    startup_res = scan_startup_programs()

    for s in startup_res["suspicious_list"]:
        if s["risk_level"] == "DANGER":
            score -= 15
        else:
            score -= 6
        findings.append({
            "category": "🚀 Startup Program",
            "title": f"โปรแกรมเริ่มระบบ: {s['name']} ({s['location']})",
            "detail": " • ".join(s["reasons"]),
            "risk_level": s["risk_level"],
            "path": s["command"]
        })

    # 3. Temp Files (75%)
    if progress_callback:
        progress_callback("กำลังตรวจสอบโฟลเดอร์ชั่วคราว (%TEMP% & AppData)...", 0.75)
    temp_res = scan_critical_temp_folders()

    for tf in temp_res["suspicious_files"][:5]:
        score -= 2
        findings.append({
            "category": "📁 Temp File",
            "title": f"ไฟล์ตกค้าง: {tf['name']} ({tf['size_mb']} MB)",
            "detail": tf["reason"],
            "risk_level": tf["risk_level"],
            "path": tf["path"]
        })

    # 4. Network Connections (100%)
    if progress_callback:
        progress_callback("กำลังตรวจสอบการเชื่อมต่อเครือข่าย (Active Network Connections)...", 0.95)
    net_res = scan_network_connections()

    for n in net_res["suspicious_list"]:
        score -= 10
        findings.append({
            "category": "🌐 Network Connection",
            "title": f"การเชื่อมต่อ: {n['process']} ➡️ {n['remote_ip']}:{n['remote_port']}",
            "detail": n["reason"],
            "risk_level": n["risk_level"],
            "path": f"PID: {n['pid']}"
        })

    score = max(10, min(100, score))

    if score >= 90 and len(findings) == 0:
        overall_status = "HEALTHY"
        status_label = "🟢 ระบบปลอดภัยดีเยี่ยม (Clean & Healthy)"
        status_color = "#16a34a"
        summary_msg = "ไม่พบโปรเซสผิดปกติ, รายการ Startup ปลอดภัย และไม่พบการเชื่อมต่อเครือข่ายที่น่าสงสัย"
    elif score >= 75:
        overall_status = "WARNING"
        status_label = "⚠️ ระบบอยู่ในเกณฑ์ดี แต่มีข้อควรระวัง (Good with Warnings)"
        status_color = "#d97706"
        summary_msg = f"ตรวจพบสิ่งตกค้างหรือข้อควรระวังจำนวน {len(findings)} รายการ แนะนำให้ตรวจสอบรายละเอียดด้านล่าง"
    else:
        overall_status = "CRITICAL"
        status_label = "🚨 ตรวจพบสิ่งผิดปกติหรือภัยคุกคามในระบบ (Threats Detected)"
        status_color = "#dc2626"
        summary_msg = f"ตรวจพบความผิดปกติระดับสูง {len(findings)} รายการ ควรรีบตรวจสอบและจัดการทันที"

    if progress_callback:
        progress_callback("การสแกนระบบเสร็จสมบูรณ์!", 1.0)

    return {
        "score": score,
        "overall_status": overall_status,
        "status_label": status_label,
        "status_color": status_color,
        "summary_msg": summary_msg,
        "process_stats": proc_res,
        "startup_stats": startup_res,
        "temp_stats": temp_res,
        "network_stats": net_res,
        "findings": findings,
        "total_findings": len(findings),
        "auto_actions_taken": auto_actions_taken
    }
