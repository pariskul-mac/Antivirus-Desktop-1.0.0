import os
import sys
import time
import threading
import psutil
from typing import Callable, Optional, Dict, Any, Set
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

from scanner_engine import scan_file

IGNORE_EXTENSIONS = {
    '.tmp', '.crdownload', '.part', '.download', '.opdownload',
    '.log', '.dat', '.ini', '.cache', '.lock', '.swp'
}


class FileScanHandler(FileSystemEventHandler):
    def __init__(self, guard_instance):
        super().__init__()
        self.guard = guard_instance
        self.recently_scanned: Dict[str, float] = {}

    def on_created(self, event):
        if not event.is_directory:
            self._handle_file(event.src_path, "ไฟล์ถูกสร้างขึ้นใหม่ (File Created)")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file(event.src_path, "ไฟล์ถูกเปลี่ยนแปลง (File Modified)")

    def _handle_file(self, file_path: str, event_type: str):
        if not os.path.exists(file_path):
            return

        # Filter temporary & browser incomplete downloads
        fname = os.path.basename(file_path)
        ext = os.path.splitext(fname)[1].lower()
        if ext in IGNORE_EXTENSIONS or fname.startswith("~$") or fname.startswith("."):
            return

        # Debounce multiple events within 3 seconds
        now = time.time()
        if file_path in self.recently_scanned and (now - self.recently_scanned[file_path]) < 3.0:
            return
        self.recently_scanned[file_path] = now

        # Run scan in worker thread so file writing can complete
        threading.Thread(target=self._async_scan_file, args=(file_path, event_type), daemon=True).start()

    def _async_scan_file(self, file_path: str, event_type: str):
        # Wait slightly for file locks / write buffers to close
        time.sleep(0.6)
        if not os.path.exists(file_path):
            return

        try:
            results = scan_file(
                file_path=file_path,
                vt_api_key=self.guard.vt_api_key,
                gemini_api_key=self.guard.gemini_api_key,
                auto_quarantine=self.guard.auto_quarantine
            )
            
            if results.get("success"):
                event_data = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "file_name": results["file_name"],
                    "file_path": file_path,
                    "event_type": event_type,
                    "risk_label": results["risk_label"],
                    "overall_risk": results["overall_risk"],
                    "size_mb": results["file_size_mb"],
                    "ai_summary": results["ai_summary"],
                    "quarantine_info": results.get("quarantine_info"),
                    "is_quarantined": bool(results.get("quarantine_info", {}).get("success"))
                }
                self.guard.dispatch_event(event_data)
        except Exception as e:
            pass


class RealTimeGuard:
    def __init__(self):
        self.is_running = False
        self.observer: Optional[Observer] = None
        self.event_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        
        self.auto_quarantine = True
        self.vt_api_key = ""
        self.gemini_api_key = ""
        
        self.known_drives: Set[str] = set()
        self.usb_thread: Optional[threading.Thread] = None

    def start(self, callback: Callable[[Dict[str, Any]], None], auto_quarantine: bool = True, vt_api_key: str = "", gemini_api_key: str = ""):
        if self.is_running:
            return

        self.event_callback = callback
        self.auto_quarantine = auto_quarantine
        self.vt_api_key = vt_api_key
        self.gemini_api_key = gemini_api_key
        self.is_running = True

        # Target Strategic Directories
        watch_dirs = [
            os.path.join(os.path.expanduser("~"), "Downloads"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]

        self.observer = Observer()
        handler = FileScanHandler(self)

        for d in watch_dirs:
            if os.path.exists(d):
                try:
                    self.observer.schedule(handler, d, recursive=False)
                except Exception:
                    pass

        try:
            self.observer.start()
        except Exception:
            pass

        # Start USB watcher thread
        self.known_drives = self._get_current_drives()
        self.usb_thread = threading.Thread(target=self._usb_monitor_loop, daemon=True)
        self.usb_thread.start()

    def stop(self):
        self.is_running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1.5)
            except Exception:
                pass
            self.observer = None

    def dispatch_event(self, event_data: Dict[str, Any]):
        if self.event_callback and self.is_running:
            try:
                self.event_callback(event_data)
            except Exception:
                pass

    def _get_current_drives(self) -> Set[str]:
        drives = set()
        try:
            for part in psutil.disk_partitions(all=False):
                drives.add(part.device.upper())
        except Exception:
            pass
        return drives

    def _usb_monitor_loop(self):
        while self.is_running:
            time.sleep(3)
            current_drives = self._get_current_drives()
            new_drives = current_drives - self.known_drives
            
            for d in new_drives:
                event_data = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "file_name": f"ตรวจพบไดรฟ์ใหม่: {d}",
                    "file_path": d,
                    "event_type": "🔌 เชื่อมต่อไดรฟ์ใหม่ (USB / Removable Drive)",
                    "risk_label": "ℹ️ ตรวจพบอุปกรณ์จัดเก็บข้อมูลใหม่",
                    "overall_risk": "INFO",
                    "size_mb": 0,
                    "ai_summary": f"ตรวจพบการเสียบอุปกรณ์ใหม่ที่ {d} แนะนำให้ตรวจสอบไฟล์ก่อนเปิดใช้งาน",
                    "is_quarantined": False
                }
                self.dispatch_event(event_data)

            self.known_drives = current_drives
