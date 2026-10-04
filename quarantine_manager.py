import os
import sys
import json
import time
import uuid
import shutil
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime

QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), ".malware_scanner_quarantine")
QUARANTINE_DB = os.path.join(QUARANTINE_DIR, "quarantine_db.json")


def _ensure_quarantine_dir():
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
    if not os.path.exists(QUARANTINE_DB):
        with open(QUARANTINE_DB, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)


def _load_db() -> List[Dict[str, Any]]:
    _ensure_quarantine_dir()
    try:
        with open(QUARANTINE_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_db(data: List[Dict[str, Any]]):
    _ensure_quarantine_dir()
    with open(QUARANTINE_DB, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def quarantine_file(file_path: str, threat_reason: str = "ตรวจพบภัยคุกคามอันตราย") -> Dict[str, Any]:
    """
    Safely isolates a suspicious file into the Quarantine Vault.
    Disables execution by changing extension and attributes.
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": "ไม่พบไฟล์ที่ต้องการกักกัน"}

    _ensure_quarantine_dir()
    item_id = str(uuid.uuid4())[:8]
    file_name = os.path.basename(file_path)
    quarantined_filename = f"{item_id}_{file_name}.locked_quarantine"
    quarantined_filepath = os.path.join(QUARANTINE_DIR, quarantined_filename)

    try:
        file_size_bytes = os.path.getsize(file_path)
        file_size_mb = round(file_size_bytes / (1024 * 1024), 2)
        
        # Move file to quarantine vault
        shutil.move(file_path, quarantined_filepath)
        
        # Strip write/execute permissions (Read-only)
        try:
            os.chmod(quarantined_filepath, 0o444)
        except Exception:
            pass

        record = {
            "id": item_id,
            "file_name": file_name,
            "original_path": os.path.abspath(file_path),
            "quarantined_path": quarantined_filepath,
            "size_mb": file_size_mb,
            "threat_reason": threat_reason,
            "quarantine_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        db = _load_db()
        db.append(record)
        _save_db(db)

        return {
            "success": True,
            "record": record,
            "message": f"ย้ายไฟล์ '{file_name}' เข้าห้องกักกันนิรภัยเรียบร้อยแล้ว"
        }
    except Exception as e:
        return {"success": False, "error": f"ไม่สามารถกักกันไฟล์ได้: {str(e)}"}


def restore_file(item_id: str) -> Dict[str, Any]:
    """
    Restores a quarantined file back to its original location.
    """
    db = _load_db()
    target_record = None
    target_index = -1

    for i, item in enumerate(db):
        if item["id"] == item_id:
            target_record = item
            target_index = i
            break

    if not target_record:
        return {"success": False, "error": "ไม่พบรายการในห้องกักกัน"}

    quarantined_path = target_record["quarantined_path"]
    original_path = target_record["original_path"]

    if not os.path.exists(quarantined_path):
        # Clean up database if file missing
        db.pop(target_index)
        _save_db(db)
        return {"success": False, "error": "ไฟล์ในห้องกักกันสูญหายหรือไม่พบ"}

    try:
        # Restore write permissions before moving
        try:
            os.chmod(quarantined_path, 0o666)
        except Exception:
            pass

        # Ensure target folder exists
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantined_path, original_path)

        # Remove from db
        db.pop(target_index)
        _save_db(db)

        return {
            "success": True,
            "file_name": target_record["file_name"],
            "original_path": original_path,
            "message": f"กู้คืนไฟล์ '{target_record['file_name']}' กลับไปยังตำแหน่งเดิมเรียบร้อยแล้ว"
        }
    except Exception as e:
        return {"success": False, "error": f"ไม่สามารถกู้คืนไฟล์ได้: {str(e)}"}


def delete_quarantined_file(item_id: str) -> Dict[str, Any]:
    """
    Permanently deletes a file from the Quarantine Vault.
    """
    db = _load_db()
    target_record = None
    target_index = -1

    for i, item in enumerate(db):
        if item["id"] == item_id:
            target_record = item
            target_index = i
            break

    if not target_record:
        return {"success": False, "error": "ไม่พบรายการในห้องกักกัน"}

    quarantined_path = target_record["quarantined_path"]

    try:
        if os.path.exists(quarantined_path):
            try:
                os.chmod(quarantined_path, 0o666)
            except Exception:
                pass
            os.remove(quarantined_path)

        db.pop(target_index)
        _save_db(db)

        return {
            "success": True,
            "file_name": target_record["file_name"],
            "message": f"ลบไฟล์ '{target_record['file_name']}' ออกจากเครื่องอย่างถาวรเรียบร้อยแล้ว"
        }
    except Exception as e:
        return {"success": False, "error": f"ไม่สามารถลบไฟล์ได้: {str(e)}"}


def delete_all_quarantined_files() -> Dict[str, Any]:
    """
    Permanently deletes all files currently stored in the Quarantine Vault.
    """
    db = _load_db()
    if not db:
        return {"success": True, "deleted_count": 0, "message": "ไม่มีไฟล์ในห้องกักกัน"}

    deleted_count = 0
    errors = []
    remaining_db = []

    for item in db:
        quarantined_path = item.get("quarantined_path", "")
        try:
            if quarantined_path and os.path.exists(quarantined_path):
                try:
                    os.chmod(quarantined_path, 0o666)
                except Exception:
                    pass
                os.remove(quarantined_path)
            deleted_count += 1
        except Exception as e:
            errors.append(f"{item.get('file_name', 'Unknown')}: {str(e)}")
            remaining_db.append(item)

    # Save only the remaining files that failed to delete (if any)
    _save_db(remaining_db)

    return {
        "success": len(errors) == 0,
        "deleted_count": deleted_count,
        "errors": errors,
        "message": f"ลบไฟล์สำเร็จ {deleted_count} รายการ" + (f" (พบข้อผิดพลาด {len(errors)} รายการ)" if errors else " (ลบทั้งหมดเรียบร้อยแล้ว)")
    }


def list_quarantined_files() -> List[Dict[str, Any]]:
    """Returns all files currently in the Quarantine Vault."""
    return _load_db()


def kill_and_quarantine_process(pid: int, threat_reason: str = "ตรวจพบโปรเซสอันตราย") -> Dict[str, Any]:
    """
    Immediately terminates a suspicious process and quarantines its executable.
    """
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        exe_path = proc.exe()
        
        # Kill the process
        proc.kill()
        proc.wait(timeout=2)
        
        quarantine_result = None
        if exe_path and os.path.exists(exe_path):
            quarantine_result = quarantine_file(exe_path, f"{threat_reason} (PID: {pid})")

        return {
            "success": True,
            "pid": pid,
            "process_name": proc_name,
            "exe_path": exe_path,
            "quarantine_result": quarantine_result,
            "message": f"หยุดการทำงานของโปรเซส '{proc_name}' (PID: {pid}) และส่งเข้าห้องกักกันเรียบร้อยแล้ว"
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"success": False, "error": f"ไม่สามารถหยุดโปรเซสได้: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
