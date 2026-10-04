import os
import sys
import subprocess
import codecs
from typing import Dict, Any, List


def get_possible_base_dirs() -> List[str]:
    """Returns all possible base directories whether running in PyInstaller onefile, onedir, or dev mode."""
    dirs = []
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            dirs.append(sys._MEIPASS)
        exe_dir = os.path.dirname(sys.executable)
        dirs.append(exe_dir)
        dirs.append(os.path.join(exe_dir, "_internal"))

    script_dir = os.path.dirname(os.path.abspath(__file__))
    dirs.append(script_dir)
    dirs.append(os.path.abspath(os.path.join(script_dir, "..")))
    dirs.append(os.getcwd())

    unique_dirs = []
    for d in dirs:
        if d and os.path.exists(d) and d not in unique_dirs:
            unique_dirs.append(d)
    return unique_dirs


def get_base_dir() -> str:
    """Returns the primary base directory."""
    dirs = get_possible_base_dirs()
    return dirs[0] if dirs else os.path.dirname(os.path.abspath(__file__))


def get_yara_binary() -> str:
    """Finds yara64.exe path across all possible locations."""
    for b in get_possible_base_dirs():
        candidates = [
            os.path.join(b, "yara_bin", "yara64.exe"),
            os.path.join(b, "yara64.exe"),
            os.path.join(b, "_internal", "yara_bin", "yara64.exe"),
            os.path.join(b, "_internal", "yara64.exe"),
            os.path.join(b, "yara_bin", "yara.exe"),
            os.path.join(b, "yara.exe")
        ]
        for c in candidates:
            if os.path.isfile(c):
                return os.path.abspath(c)
    return ""


def get_yara_rules_dir() -> str:
    """Returns the directory containing YARA rules across all possible locations."""
    for b in get_possible_base_dirs():
        candidates = [
            os.path.join(b, "yara_rules"),
            os.path.join(b, "_internal", "yara_rules"),
            os.path.join(b, "yara_rules", "yara_rules")
        ]
        for c in candidates:
            if os.path.isdir(c) and os.path.isfile(os.path.join(c, "index.yar")):
                return os.path.abspath(c)
    return ""


def get_yara_rules_index() -> str:
    """Finds index.yar path."""
    r_dir = get_yara_rules_dir()
    if r_dir:
        idx = os.path.join(r_dir, "index.yar")
        if os.path.isfile(idx):
            return os.path.abspath(idx)
    return ""


def _decode_yara_meta(text: str) -> str:
    """Decodes octal escapes from YARA CLI output into human readable UTF-8 string."""
    try:
        if "\\" in text:
            return codecs.escape_decode(text.encode('latin1'))[0].decode('utf-8')
    except Exception:
        pass
    return text


def run_yara_scan(file_path: str) -> Dict[str, Any]:
    """
    Executes YARA rules against the target file.
    Returns parsed rule matches and threat metadata.
    """
    yara_exe = get_yara_binary()
    rules_index = get_yara_rules_index()

    if not yara_exe or not os.path.exists(yara_exe):
        return {
            "available": False,
            "error": "yara64.exe binary not found",
            "matched": False,
            "matches": [],
            "matched_rules_count": 0,
            "summary": "YARA Engine ไม่พร้อมใช้งาน (ไม่พบบายนารี yara64.exe)"
        }

    if not rules_index or not os.path.exists(rules_index):
        return {
            "available": False,
            "error": "index.yar rules file not found",
            "matched": False,
            "matches": [],
            "matched_rules_count": 0,
            "summary": "YARA Rules ไม่พร้อมใช้งาน (ไม่พบไฟล์ index.yar)"
        }

    if not os.path.exists(file_path):
        return {
            "available": True,
            "matched": False,
            "matches": [],
            "matched_rules_count": 0,
            "summary": "ไม่พบไฟล์เป้าหมาย"
        }

    try:
        rules_dir = os.path.dirname(rules_index)
        cmd = [yara_exe, "-m", os.path.basename(rules_index), os.path.abspath(file_path)]

        proc = subprocess.run(
            cmd,
            cwd=rules_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        output = proc.stdout.strip()
        matches: List[Dict[str, Any]] = []

        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 1)
                rule_name = parts[0].strip()
                
                desc = "ตรวจพบลักษณะตรงตามกฎความปลอดภัย"
                severity = "DANGER"
                
                if len(parts) > 1:
                    rest = parts[1]
                    if "[" in rest and "]" in rest:
                        meta_str = rest[rest.find("[") + 1 : rest.rfind("]")]
                        for m_item in meta_str.split(","):
                            if "=" in m_item:
                                k, v = m_item.split("=", 1)
                                k = k.strip()
                                v = v.strip().strip('"').strip("'")
                                if k == "description":
                                    desc = _decode_yara_meta(v)
                                elif k == "severity":
                                    severity = v.upper()

                matches.append({
                    "rule": rule_name,
                    "description": desc,
                    "severity": severity
                })

        # Check if YARA failed with a compilation/syntax error
        if proc.returncode != 0 and not matches:
            err_text = proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"
            return {
                "available": False,
                "error": err_text,
                "matched": False,
                "matches": [],
                "matched_rules_count": 0,
                "summary": f"YARA Engine ตรวจสอบไม่สำเร็จ (เกิดข้อผิดพลาดในกฎ Signatures): {err_text[:100]}"
            }

        has_match = len(matches) > 0
        if has_match:
            rule_names = ", ".join([m["rule"] for m in matches[:3]])
            summary = f"🚨 YARA Match ({len(matches)} กฎ): {rule_names}"
        else:
            summary = "✅ ผ่านการตรวจสอบ ไม่พบสิ่งผิดปกติตามกฎ YARA Signatures"

        return {
            "available": True,
            "matched": has_match,
            "matches": matches,
            "matched_rules_count": len(matches),
            "summary": summary
        }

    except Exception as e:
        return {
            "available": True,
            "error": str(e),
            "matched": False,
            "matches": [],
            "matched_rules_count": 0,
            "summary": f"เกิดข้อผิดพลาดในการรัน YARA: {str(e)}"
        }
