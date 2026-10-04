import os
import sys
import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

import pystray
from pystray import MenuItem as item

from scanner_engine import scan_file, ask_gemini_chat, MAX_FILE_SIZE_MB
from system_scanner_engine import run_full_system_scan
from quarantine_manager import list_quarantined_files, restore_file, delete_quarantined_file, quarantine_file, delete_all_quarantined_files
from realtime_guard import RealTimeGuard
from tray_helper import create_shield_icon_image, set_start_with_windows, is_start_with_windows_enabled
from yara_engine import get_yara_rules_dir
from i18n import t

# Set Modern Light Theme
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".malware_scanner_config.json")


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "vt_api_key": "",
        "gemini_api_key": "",
        "auto_quarantine": True,
        "realtime_enabled": True,
        "start_with_windows": is_start_with_windows_enabled(),
        "language": "th"
    }


def save_config(vt_key, gemini_key, auto_quarantine=True, realtime_enabled=True, start_with_windows=False, language="th"):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "vt_api_key": vt_key.strip(),
                "gemini_api_key": gemini_key.strip(),
                "auto_quarantine": auto_quarantine,
                "realtime_enabled": realtime_enabled,
                "start_with_windows": start_with_windows,
                "language": language
            }, f)
    except Exception:
        pass


class ApiSettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent, current_vt_key, current_gemini_key, current_auto_q, current_realtime, current_boot, current_lang, on_save_callback):
        super().__init__(parent)
        self.current_lang = current_lang
        self.on_save_callback = on_save_callback

        self.title(t("settings_dialog_title", self.current_lang))
        self.geometry("580x540")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frame = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16, border_width=1, border_color="#e2e8f0")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.dlg_title = ctk.CTkLabel(
            frame,
            text=t("settings_dialog_header", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
            text_color="#0f172a"
        )
        self.dlg_title.pack(anchor="w", padx=24, pady=(16, 4))

        self.dlg_desc = ctk.CTkLabel(
            frame,
            text=t("settings_dialog_desc", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#64748b",
            justify="left"
        )
        self.dlg_desc.pack(anchor="w", padx=24, pady=(0, 10))

        # Language Selector Row
        lang_frame = ctk.CTkFrame(frame, fg_color="#f8fafc", corner_radius=8, border_width=1, border_color="#e2e8f0")
        lang_frame.pack(fill="x", padx=24, pady=(0, 10))

        self.lbl_lang = ctk.CTkLabel(
            lang_frame,
            text=t("lbl_language", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#1e293b"
        )
        self.lbl_lang.pack(side="left", padx=12, pady=8)

        self.lang_var = ctk.StringVar(value="🇹🇭 ไทย" if self.current_lang == "th" else "🇬🇧 English")
        self.lang_seg = ctk.CTkSegmentedButton(
            lang_frame,
            values=["🇹🇭 ไทย", "🇬🇧 English"],
            variable=self.lang_var,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            selected_color="#0284c7",
            selected_hover_color="#0369a1",
            height=30,
            command=self._on_lang_switch
        )
        self.lang_seg.pack(side="right", padx=12, pady=8)

        # VirusTotal Key
        self.vt_lbl = ctk.CTkLabel(frame, text=t("lbl_vt_key", self.current_lang), font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"), text_color="#334155")
        self.vt_lbl.pack(anchor="w", padx=24, pady=(2, 2))
        self.vt_entry = ctk.CTkEntry(frame, show="•", width=520, height=34, corner_radius=8, placeholder_text=t("ph_vt_key", self.current_lang))
        self.vt_entry.pack(padx=24, pady=(0, 8))
        self.vt_entry.insert(0, current_vt_key)

        # Gemini Key
        self.gm_lbl = ctk.CTkLabel(frame, text=t("lbl_gemini_key", self.current_lang), font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"), text_color="#334155")
        self.gm_lbl.pack(anchor="w", padx=24, pady=(2, 2))
        self.gm_entry = ctk.CTkEntry(frame, show="•", width=520, height=34, corner_radius=8, placeholder_text=t("ph_gemini_key", self.current_lang))
        self.gm_entry.pack(padx=24, pady=(0, 10))
        self.gm_entry.insert(0, current_gemini_key)

        # Switches
        self.realtime_switch = ctk.CTkSwitch(
            frame,
            text=t("switch_realtime", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#0f172a",
            progress_color="#0284c7"
        )
        self.realtime_switch.pack(anchor="w", padx=24, pady=(2, 6))
        if current_realtime:
            self.realtime_switch.select()
        else:
            self.realtime_switch.deselect()

        self.auto_switch = ctk.CTkSwitch(
            frame,
            text=t("switch_auto_defense", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#0f172a",
            progress_color="#0284c7"
        )
        self.auto_switch.pack(anchor="w", padx=24, pady=(0, 6))
        if current_auto_q:
            self.auto_switch.select()
        else:
            self.auto_switch.deselect()

        self.boot_switch = ctk.CTkSwitch(
            frame,
            text=t("switch_boot", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#0f172a",
            progress_color="#0284c7"
        )
        self.boot_switch.pack(anchor="w", padx=24, pady=(0, 12))
        if current_boot:
            self.boot_switch.select()
        else:
            self.boot_switch.deselect()

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=24, pady=(0, 12))

        self.btn_yara = ctk.CTkButton(
            btn_frame,
            text=t("btn_open_yara", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#f1f5f9",
            hover_color="#e2e8f0",
            text_color="#334155",
            height=34,
            corner_radius=8,
            command=self.open_yara_folder
        )
        self.btn_yara.pack(side="left")

        self.btn_save = ctk.CTkButton(
            btn_frame,
            text=t("btn_save", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=34,
            corner_radius=8,
            command=self.save_and_close
        )
        self.btn_save.pack(side="right", padx=5)

        self.btn_cancel = ctk.CTkButton(
            btn_frame,
            text=t("btn_cancel", self.current_lang),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="#f1f5f9",
            hover_color="#e2e8f0",
            text_color="#334155",
            height=34,
            corner_radius=8,
            command=self.destroy
        )
        self.btn_cancel.pack(side="right", padx=5)

    def _on_lang_switch(self, value):
        new_lang = "th" if "ไทย" in value else "en"
        self.current_lang = new_lang
        self.title(t("settings_dialog_title", new_lang))
        self.dlg_title.configure(text=t("settings_dialog_header", new_lang))
        self.dlg_desc.configure(text=t("settings_dialog_desc", new_lang))
        self.lbl_lang.configure(text=t("lbl_language", new_lang))
        self.vt_lbl.configure(text=t("lbl_vt_key", new_lang))
        self.gm_lbl.configure(text=t("lbl_gemini_key", new_lang))
        self.realtime_switch.configure(text=t("switch_realtime", new_lang))
        self.auto_switch.configure(text=t("switch_auto_defense", new_lang))
        self.boot_switch.configure(text=t("switch_boot", new_lang))
        self.btn_yara.configure(text=t("btn_open_yara", new_lang))
        self.btn_save.configure(text=t("btn_save", new_lang))
        self.btn_cancel.configure(text=t("btn_cancel", new_lang))

    def open_yara_folder(self):
        r_dir = get_yara_rules_dir()
        if r_dir and os.path.exists(r_dir):
            os.startfile(r_dir)
        else:
            messagebox.showinfo("YARA Rules", f"Folder path:\n{r_dir}")

    def save_and_close(self):
        vt_k = self.vt_entry.get().strip()
        gm_k = self.gm_entry.get().strip()
        auto_q = bool(self.auto_switch.get())
        rt_en = bool(self.realtime_switch.get())
        boot_en = bool(self.boot_switch.get())
        lang = "th" if "ไทย" in self.lang_var.get() else "en"
        
        # Apply Windows boot registry
        set_start_with_windows(boot_en)
        save_config(vt_k, gm_k, auto_q, rt_en, boot_en, lang)
        self.on_save_callback(vt_k, gm_k, auto_q, rt_en, boot_en, lang)
        self.destroy()


class MalwareScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ CyberGuard AI - Advanced Malware & System Security")
        self.geometry("1160x860")
        self.minsize(1000, 720)
        self.configure(fg_color="#f8fafc")

        # Load Config
        config = load_config()
        self.vt_api_key = config.get("vt_api_key", "")
        self.gemini_api_key = config.get("gemini_api_key", "")
        self.auto_quarantine = config.get("auto_quarantine", True)
        self.realtime_enabled = config.get("realtime_enabled", True)
        self.start_with_windows = config.get("start_with_windows", False)
        self.language = config.get("language", "th")

        self.selected_file_path = None
        self.is_file_scanning = False
        self.is_system_scanning = False
        
        self.current_file_result = None
        self.current_system_result = None
        self.chat_history = []
        self.thinking_card = None

        # Real-time Guard & Event Tracking
        self.realtime_guard = RealTimeGuard()
        self.realtime_events = []
        self.rt_total_count = 0
        self.rt_clean_count = 0
        self.rt_danger_count = 0

        # System Tray Icon Instance
        self.tray_icon = None
        self._init_system_tray()

        self.current_view_name = "file_scan"
        self.nav_buttons = {}

        self._create_sidebar_layout()
        self.show_view("file_scan")

        # Start Realtime Guard if enabled
        if self.realtime_enabled:
            self._start_realtime_guard()

        # Handle window close (Minimize to Tray instead of terminating)
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        # Check if launched with --minimized flag (from Windows startup)
        if "--minimized" in sys.argv:
            self.after(100, self.withdraw)

    # =========================================================================
    # SYSTEM TRAY & NOTIFICATION LOGIC
    # =========================================================================
    def _init_system_tray(self):
        icon_img = create_shield_icon_image()
        
        menu = pystray.Menu(
            item("🛡️ เปิดหน้าต่างหลัก (Open CyberGuard)", self.show_main_window, default=True),
            pystray.Menu.SEPARATOR,
            item("⚡ Auto-Defense Mode", lambda: None, enabled=False),
            item("🟢 Real-Time Shield Active", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            item("❌ ปิดโปรแกรมถาวร (Quit App)", self.quit_application)
        )
        
        self.tray_icon = pystray.Icon(
            "CyberGuardAI",
            icon_img,
            "CyberGuard AI - ป้องกันคอมพิวเตอร์แบบเรียลไทม์",
            menu
        )
        
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def hide_to_tray(self):
        self.withdraw()
        if self.tray_icon:
            title_msg = "🛡️ CyberGuard AI Running in Background" if self.language == "en" else "🛡️ CyberGuard AI กำลังทำงานในพื้นหลัง"
            body_msg = "Application minimized to system tray and actively protecting your system." if self.language == "en" else "โปรแกรมถูกย่อลงถาดระบบ (System Tray) และยังคงเฝ้าระวังความปลอดภัยให้อย่างต่อเนื่อง"
            self.send_toast(title_msg, body_msg)

    def show_main_window(self, icon=None, item=None):
        self.after(0, self._restore_window_ui)

    def _restore_window_ui(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_application(self, icon=None, item=None):
        try:
            self.realtime_guard.stop()
        except Exception:
            pass
        if self.tray_icon:
            self.tray_icon.stop()
        self.after(0, self.destroy)

    def send_toast(self, title: str, message: str):
        if self.tray_icon:
            try:
                self.tray_icon.notify(message=message, title=title)
            except Exception:
                pass

    # =========================================================================
    # LAYOUT & NAVIGATION
    # =========================================================================
    def _create_sidebar_layout(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. LEFT SIDEBAR FRAME
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=240,
            corner_radius=0,
            fg_color="#ffffff",
            border_width=1,
            border_color="#e2e8f0"
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        # App Brand Header
        brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        brand_frame.pack(fill="x", padx=16, pady=(20, 16))

        brand_logo = ctk.CTkLabel(brand_frame, text="🛡️", font=ctk.CTkFont(size=24))
        brand_logo.pack(side="left", padx=(0, 8))

        brand_title_box = ctk.CTkFrame(brand_frame, fg_color="transparent")
        brand_title_box.pack(side="left")

        self.app_brand_title = ctk.CTkLabel(
            brand_title_box,
            text=t("app_title", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color="#0284c7"
        )
        self.app_brand_title.pack(anchor="w")

        self.app_sub_title = ctk.CTkLabel(
            brand_title_box,
            text=t("app_sub", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color="#64748b"
        )
        self.app_sub_title.pack(anchor="w")

        div1 = ctk.CTkFrame(self.sidebar_frame, height=1, fg_color="#f1f5f9")
        div1.pack(fill="x", padx=16, pady=(0, 12))

        self.nav_section_lbl = ctk.CTkLabel(
            self.sidebar_frame,
            text=t("nav_section", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#94a3b8"
        )
        self.nav_section_lbl.pack(anchor="w", padx=20, pady=(0, 6))

        # Nav Buttons (6 Features)
        self._create_nav_button("file_scan", t("nav_file_scan", self.language), self.sidebar_frame)
        self._create_nav_button("system_scan", t("nav_system_scan", self.language), self.sidebar_frame)
        self._create_nav_button("realtime", t("nav_realtime", self.language), self.sidebar_frame)
        self._create_nav_button("quarantine", t("nav_quarantine", self.language), self.sidebar_frame)
        self._create_nav_button("chat", t("nav_chat", self.language), self.sidebar_frame)
        self._create_nav_button("log", t("nav_log", self.language), self.sidebar_frame)

        # Bottom Sidebar Container
        bottom_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", padx=14, pady=16)

        # Auto-Defense Card
        auto_card = ctk.CTkFrame(bottom_frame, corner_radius=10, fg_color="#f8fafc", border_width=1, border_color="#e2e8f0")
        auto_card.pack(fill="x", pady=(0, 10))

        self.sidebar_auto_lbl = ctk.CTkLabel(
            auto_card,
            text=t("sidebar_auto_title", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#0f172a"
        )
        self.sidebar_auto_lbl.pack(anchor="w", padx=12, pady=(10, 2))

        self.sidebar_auto_switch = ctk.CTkSwitch(
            auto_card,
            text=t("sidebar_auto_switch", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#64748b",
            progress_color="#0284c7",
            command=self._on_sidebar_auto_toggle
        )
        self.sidebar_auto_switch.pack(anchor="w", padx=12, pady=(0, 10))
        if self.auto_quarantine:
            self.sidebar_auto_switch.select()
        else:
            self.sidebar_auto_switch.deselect()

        # Settings Button
        self.sidebar_settings_btn = ctk.CTkButton(
            bottom_frame,
            text=t("sidebar_settings_btn", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#f8fafc",
            hover_color="#f1f5f9",
            text_color="#334155",
            border_width=1,
            border_color="#cbd5e1",
            height=34,
            corner_radius=8,
            command=self.open_settings
        )
        self.sidebar_settings_btn.pack(fill="x")

        # 2. RIGHT MAIN CONTENT AREA
        self.main_container = ctk.CTkFrame(self, fg_color="#f8fafc", corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

        # Main Header Bar
        self.main_header = ctk.CTkFrame(self.main_container, height=60, fg_color="#ffffff", border_width=1, border_color="#e2e8f0", corner_radius=0)
        self.main_header.grid(row=0, column=0, sticky="ew")
        self.main_header.grid_columnconfigure(0, weight=1)

        self.header_title = ctk.CTkLabel(
            self.main_header,
            text=t("title_file_scan", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color="#0f172a"
        )
        self.header_title.grid(row=0, column=0, padx=24, pady=16, sticky="w")

        self.live_status_badge = ctk.CTkLabel(
            self.main_header,
            text=t("status_ready", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#dcfce7",
            text_color="#166534",
            corner_radius=8,
            height=28,
            padx=12
        )
        self.live_status_badge.grid(row=0, column=1, padx=24, pady=16, sticky="e")

        # Views Frame Container
        self.views_container = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=14)
        self.views_container.grid_columnconfigure(0, weight=1)
        self.views_container.grid_rowconfigure(0, weight=1)

        self.view_frames = {}
        self._build_file_scan_view()
        self._build_system_scan_view()
        self._build_realtime_view()
        self._build_quarantine_view()
        self._build_chat_view()
        self._build_log_view()

    def _create_nav_button(self, name, label, parent):
        btn = ctk.CTkButton(
            parent,
            text=label,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color="transparent",
            hover_color="#f1f5f9",
            text_color="#475569",
            anchor="w",
            height=38,
            corner_radius=10,
            command=lambda n=name: self.show_view(n)
        )
        btn.pack(fill="x", padx=12, pady=2)
        self.nav_buttons[name] = btn

    def show_view(self, view_name):
        self.current_view_name = view_name

        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.configure(fg_color="#0284c7", text_color="#ffffff", hover_color="#0369a1")
            else:
                btn.configure(fg_color="transparent", text_color="#475569", hover_color="#f1f5f9")

        for name, frame in self.view_frames.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_remove()

        titles = {
            "file_scan": t("title_file_scan", self.language),
            "system_scan": t("title_system_scan", self.language),
            "realtime": t("title_realtime", self.language),
            "quarantine": t("title_quarantine", self.language),
            "chat": t("title_chat", self.language),
            "log": t("title_log", self.language)
        }
        self.header_title.configure(text=titles.get(view_name, "CyberGuard AI"))

        if view_name == "quarantine":
            self.refresh_quarantine_list()

    def apply_language(self, lang: str):
        """Applies the selected language across all GUI widgets dynamically."""
        self.language = lang

        # Header bar & Branding
        self.app_brand_title.configure(text=t("app_title", lang))
        self.app_sub_title.configure(text=t("app_sub", lang))
        self.live_status_badge.configure(text=t("status_ready", lang))
        self.nav_section_lbl.configure(text=t("nav_section", lang))

        # Nav Buttons
        self.nav_buttons["file_scan"].configure(text=t("nav_file_scan", lang))
        self.nav_buttons["system_scan"].configure(text=t("nav_system_scan", lang))
        self.nav_buttons["realtime"].configure(text=t("nav_realtime", lang))
        
        items = list_quarantined_files()
        badge_txt = t("nav_quarantine", lang) + (f" [{len(items)}]" if len(items) > 0 else "")
        self.nav_buttons["quarantine"].configure(text=badge_txt)
        self.nav_buttons["chat"].configure(text=t("nav_chat", lang))
        self.nav_buttons["log"].configure(text=t("nav_log", lang))

        # Sidebar Bottom
        self.sidebar_auto_lbl.configure(text=t("sidebar_auto_title", lang))
        self.sidebar_auto_switch.configure(text=t("sidebar_auto_switch", lang))
        self.sidebar_settings_btn.configure(text=t("sidebar_settings_btn", lang))

        # View Header Title
        self.show_view(self.current_view_name)

        # File Scanner Widgets
        self.btn_browse.configure(text=t("btn_browse", lang))
        self.path_entry.configure(placeholder_text=t("placeholder_path", lang))
        self.btn_file_scan.configure(text=t("btn_start_file_scan", lang))
        if not self.current_file_result:
            self.file_risk_lbl.configure(text=t("risk_ready", lang))
            self.file_ai_summary.configure(text=t("file_ai_placeholder", lang))
        self.btn_quick_ask_ai_file.configure(text=t("btn_ask_ai_file", lang))
        if hasattr(self, "btn_manual_quarantine"):
            if self.btn_manual_quarantine.cget("state") == "disabled":
                self.btn_manual_quarantine.configure(text=t("btn_already_quarantined", lang))
            else:
                self.btn_manual_quarantine.configure(text=t("btn_manual_quarantine", lang))
        self.file_ai_card_header.configure(text=t("file_ai_card_header", lang))

        self.fm1.title_label.configure(text=t("metric_size", lang))
        self.fm2.title_label.configure(text=t("metric_entropy", lang))
        self.fm3.title_label.configure(text=t("metric_vt_detected", lang))
        self.fm4.title_label.configure(text=t("metric_vt_clean", lang))

        self.check_title.configure(text=t("chk_title", lang))
        self.chk_magic.title_label.configure(text=t("chk_magic_lbl", lang))
        self.chk_dext.title_label.configure(text=t("chk_dext_lbl", lang))
        self.chk_entropy.title_label.configure(text=t("chk_entropy_lbl", lang))
        self.chk_pe.title_label.configure(text=t("chk_pe_lbl", lang))
        self.chk_strings.title_label.configure(text=t("chk_strings_lbl", lang))
        self.chk_yara.title_label.configure(text=t("chk_yara_lbl", lang))

        # System Scanner Widgets
        self.btn_sys_scan.configure(text=t("btn_start_sys_scan", lang))
        if not self.current_system_result:
            self.sys_status_lbl.configure(text=t("sys_status_ready", lang))
            self.sys_health_title.configure(text=t("sys_health_default", lang))
            self.sys_health_desc.configure(text=t("sys_health_desc_default", lang))
        self.btn_quick_ask_ai_sys.configure(text=t("btn_ask_ai_sys", lang))

        self.sm1.title_label.configure(text=t("sm_processes", lang))
        self.sm2.title_label.configure(text=t("sm_startup", lang))
        self.sm3.title_label.configure(text=t("sm_temp", lang))
        self.sm4.title_label.configure(text=t("sm_network", lang))
        self.findings_header.configure(text=t("findings_header", lang))

        # Real-Time Shield Widgets
        self.rt_main_switch.configure(text=t("rt_switch_lbl", lang))
        self.rt_m1.title_label.configure(text=t("rt_metric_total", lang))
        self.rt_m2.title_label.configure(text=t("rt_metric_clean", lang))
        self.rt_m3.title_label.configure(text=t("rt_metric_danger", lang))
        self.rt_stream_title.configure(text=t("rt_stream_title", lang))
        self.btn_clear_stream.configure(text=t("btn_clear", lang))

        if self.realtime_enabled:
            self.rt_status_title.configure(text=t("rt_active_title", lang))
            self.rt_status_desc.configure(text=t("rt_active_desc", lang))
        else:
            self.rt_status_title.configure(text=t("rt_paused_title", lang))
            self.rt_status_desc.configure(text=t("rt_paused_desc", lang))

        # Quarantine View
        self.refresh_quarantine_list()

        # Chatbot View
        self.chat_assistant_info.configure(text=t("chat_assistant_info", lang))
        self.btn_clear_chat.configure(text=t("btn_clear", lang))
        self.chip_label.configure(text=t("chip_label", lang))
        self.chip_btn_1.configure(text=t("chip_1", lang))
        self.chip_btn_2.configure(text=t("chip_2", lang))
        self.chip_btn_3.configure(text=t("chip_3", lang))
        self.chat_input.configure(placeholder_text=t("chat_placeholder", lang))
        self.btn_send_chat.configure(text=t("btn_send", lang))

    def _on_sidebar_auto_toggle(self):
        self.auto_quarantine = bool(self.sidebar_auto_switch.get())
        save_config(self.vt_api_key, self.gemini_api_key, self.auto_quarantine, self.realtime_enabled, self.start_with_windows, self.language)
        status_text = "Enabled" if (self.language == "en" and self.auto_quarantine) else ("Disabled" if self.language == "en" else ("เปิดทำงาน" if self.auto_quarantine else "ปิดทำงาน"))
        messagebox.showinfo(t("settings_dialog_title", self.language), f"Auto-Defense: {status_text}")

    def go_to_chat_with_prompt(self, prompt_text: str = ""):
        self.show_view("chat")
        if prompt_text:
            self.chat_input.delete(0, "end")
            self.chat_input.insert(0, prompt_text)
            self.chat_input.focus_set()

    # =========================================================================
    # REALTIME GUARD ENGINE INTEGRATION
    # =========================================================================
    def _start_realtime_guard(self):
        self.realtime_guard.start(
            callback=self._handle_realtime_event,
            auto_quarantine=self.auto_quarantine,
            vt_api_key=self.vt_api_key,
            gemini_api_key=self.gemini_api_key
        )

    def _handle_realtime_event(self, event_data: dict):
        self.after(0, self._process_realtime_event_ui, event_data)

    def _process_realtime_event_ui(self, event_data: dict):
        self.realtime_events.insert(0, event_data)
        self.rt_total_count += 1
        
        fname = event_data["file_name"]
        risk = event_data["overall_risk"]

        if risk == "DANGER":
            self.rt_danger_count += 1
            if event_data.get("is_quarantined"):
                self.refresh_quarantine_list()
                t_title = "🚨 CyberGuard: Threat Quarantined!" if self.language == "en" else "🚨 CyberGuard: ตรวจพบและกักกันมัลแวร์แล้ว!"
                t_body = f"File '{fname}' isolated to vault." if self.language == "en" else f"ไฟล์ '{fname}' ถูกล็อคและย้ายเข้าห้องกักกันให้อัตโนมัติ"
                self.send_toast(t_title, t_body)
            else:
                t_title = "🚨 CyberGuard: Danger Threat Detected!" if self.language == "en" else "🚨 CyberGuard: ตรวจพบไฟล์อันตราย!"
                t_body = f"File '{fname}' exhibits high risk." if self.language == "en" else f"ไฟล์ '{fname}' มีความเสี่ยงระดับสูง กรุณาตรวจสอบ"
                self.send_toast(t_title, t_body)
        elif risk == "WARNING":
            t_title = "⚠️ CyberGuard: Suspicious File" if self.language == "en" else "⚠️ CyberGuard: ตรวจพบไฟล์ต้องสงสัย"
            t_body = f"File '{fname}' requires caution." if self.language == "en" else f"ไฟล์ '{fname}' มีข้อควรระวัง กรุณาตรวจสอบก่อนเปิด"
            self.send_toast(t_title, t_body)
        else:
            self.rt_clean_count += 1
            t_title = "🟢 CyberGuard: File Verified Safe" if self.language == "en" else "🟢 CyberGuard: สแกนไฟล์ใหม่เรียบร้อย"
            t_body = f"File '{fname}' is clean." if self.language == "en" else f"ไฟล์ '{fname}' ปลอดภัย สะอาด 100%"
            self.send_toast(t_title, t_body)

        self._render_realtime_stream()
        self._append_log(f"[{event_data['timestamp']}] [Real-Time Event] {fname} -> {event_data['risk_label']}")

    # =========================================================================
    # VIEW 1: FILE SCANNER
    # =========================================================================
    def _build_file_scan_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)
        self.view_frames["file_scan"] = view

        control_frame = ctk.CTkFrame(view, corner_radius=12, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        control_frame.grid_columnconfigure(1, weight=1)

        self.btn_browse = ctk.CTkButton(
            control_frame,
            text=t("btn_browse", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=38,
            corner_radius=8,
            width=150,
            command=self.browse_file
        )
        self.btn_browse.grid(row=0, column=0, padx=14, pady=12)

        self.path_entry = ctk.CTkEntry(
            control_frame,
            placeholder_text=t("placeholder_path", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            state="readonly",
            height=38,
            corner_radius=8,
            fg_color="#f8fafc",
            border_color="#cbd5e1"
        )
        self.path_entry.grid(row=0, column=1, padx=(0, 10), pady=12, sticky="ew")

        self.btn_file_scan = ctk.CTkButton(
            control_frame,
            text=t("btn_start_file_scan", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669",
            height=38,
            corner_radius=8,
            width=165,
            state="disabled",
            command=self.start_file_scan_thread
        )
        self.btn_file_scan.grid(row=0, column=2, padx=14, pady=12)

        self.file_progress = ctk.CTkProgressBar(control_frame, mode="indeterminate", height=4, corner_radius=2)
        self.file_progress.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 8), sticky="ew")
        self.file_progress.set(0)

        self.file_scroll = ctk.CTkScrollableFrame(view, fg_color="transparent")
        self.file_scroll.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.file_scroll.grid_columnconfigure(0, weight=1)

        # Risk Banner Card
        self.file_risk_card = ctk.CTkFrame(self.file_scroll, corner_radius=12, fg_color="#ffffff", border_width=2, border_color="#e2e8f0")
        self.file_risk_card.pack(fill="x", pady=(0, 10))
        self.file_risk_card.grid_columnconfigure(0, weight=1)

        risk_top_row = ctk.CTkFrame(self.file_risk_card, fg_color="transparent")
        risk_top_row.pack(fill="x", padx=18, pady=12)
        risk_top_row.grid_columnconfigure(0, weight=1)

        self.file_risk_lbl = ctk.CTkLabel(
            risk_top_row,
            text=t("risk_ready", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color="#475569"
        )
        self.file_risk_lbl.grid(row=0, column=0, sticky="w")

        self.btn_manual_quarantine = ctk.CTkButton(
            risk_top_row,
            text=t("btn_manual_quarantine", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=32,
            corner_radius=8,
            command=self.manual_quarantine_current_file
        )
        self.btn_manual_quarantine.grid(row=0, column=1, padx=(0, 8), sticky="e")
        self.btn_manual_quarantine.grid_remove()

        self.btn_quick_ask_ai_file = ctk.CTkButton(
            risk_top_row,
            text=t("btn_ask_ai_file", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=32,
            corner_radius=8,
            command=lambda: self.go_to_chat_with_prompt(
                "Is this recently scanned file safe? What behaviors should I watch out for?" if self.language == "en" else "ไฟล์ที่เพิ่งสแกนนี้ปลอดภัยไหม มีพฤติกรรมอะไรที่ต้องระวังบ้าง?"
            )
        )
        self.btn_quick_ask_ai_file.grid(row=0, column=2, sticky="e")
        self.btn_quick_ask_ai_file.grid_remove()

        # AI Summary Card
        self.file_ai_card = ctk.CTkFrame(self.file_scroll, corner_radius=12, fg_color="#f0fdf4", border_width=1, border_color="#bbf7d0")
        self.file_ai_card.pack(fill="x", pady=(0, 10))
        self.file_ai_card.grid_columnconfigure(0, weight=1)

        self.file_ai_card_header = ctk.CTkLabel(
            self.file_ai_card,
            text=t("file_ai_card_header", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#166534"
        )
        self.file_ai_card_header.pack(anchor="w", padx=18, pady=(12, 4))

        self.file_ai_summary = ctk.CTkLabel(
            self.file_ai_card,
            text=t("file_ai_placeholder", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#1e293b",
            wraplength=800,
            justify="left"
        )
        self.file_ai_summary.pack(anchor="w", padx=18, pady=(0, 14))

        # Metrics Grid
        metrics_frame = ctk.CTkFrame(self.file_scroll, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=(0, 10))
        metrics_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.fm1 = self._create_metric_box(metrics_frame, 0, t("metric_size", self.language), "0.00 MB", "#0284c7")
        self.fm2 = self._create_metric_box(metrics_frame, 1, t("metric_entropy", self.language), "0.0 / 8.0", "#6366f1")
        self.fm3 = self._create_metric_box(metrics_frame, 2, t("metric_vt_detected", self.language), "0", "#ef4444")
        self.fm4 = self._create_metric_box(metrics_frame, 3, t("metric_vt_clean", self.language), "0", "#10b981")

        # Checklist
        check_frame = ctk.CTkFrame(self.file_scroll, corner_radius=12, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        check_frame.pack(fill="x", pady=(0, 10))
        check_frame.grid_columnconfigure(0, weight=1)

        self.check_title = ctk.CTkLabel(
            check_frame,
            text=t("chk_title", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#0f172a"
        )
        self.check_title.pack(anchor="w", padx=18, pady=(12, 6))

        not_scanned_txt = t("chk_not_scanned", self.language)
        self.chk_magic = self._create_check_row(check_frame, t("chk_magic_lbl", self.language), not_scanned_txt)
        self.chk_dext = self._create_check_row(check_frame, t("chk_dext_lbl", self.language), not_scanned_txt)
        self.chk_entropy = self._create_check_row(check_frame, t("chk_entropy_lbl", self.language), not_scanned_txt)
        self.chk_pe = self._create_check_row(check_frame, t("chk_pe_lbl", self.language), not_scanned_txt)
        self.chk_strings = self._create_check_row(check_frame, t("chk_strings_lbl", self.language), not_scanned_txt)
        self.chk_yara = self._create_check_row(check_frame, t("chk_yara_lbl", self.language), not_scanned_txt)

    # =========================================================================
    # VIEW 2: SYSTEM SECURITY SCANNER
    # =========================================================================
    def _build_system_scan_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)
        self.view_frames["system_scan"] = view

        sys_top = ctk.CTkFrame(view, corner_radius=12, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        sys_top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        sys_top.grid_columnconfigure(1, weight=1)

        self.btn_sys_scan = ctk.CTkButton(
            sys_top,
            text=t("btn_start_sys_scan", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=40,
            corner_radius=10,
            width=290,
            command=self.start_system_scan_thread
        )
        self.btn_sys_scan.grid(row=0, column=0, padx=14, pady=12)

        self.sys_status_lbl = ctk.CTkLabel(
            sys_top,
            text=t("sys_status_ready", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#475569"
        )
        self.sys_status_lbl.grid(row=0, column=1, padx=10, pady=12, sticky="w")

        self.sys_progress = ctk.CTkProgressBar(sys_top, mode="determinate", height=4, corner_radius=2)
        self.sys_progress.grid(row=1, column=0, columnspan=2, padx=14, pady=(0, 8), sticky="ew")
        self.sys_progress.set(0)

        self.sys_scroll = ctk.CTkScrollableFrame(view, fg_color="transparent")
        self.sys_scroll.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.sys_scroll.grid_columnconfigure(0, weight=1)

        # Health Banner Card
        self.sys_health_card = ctk.CTkFrame(self.sys_scroll, corner_radius=14, fg_color="#ffffff", border_width=2, border_color="#e2e8f0")
        self.sys_health_card.pack(fill="x", pady=(0, 12))
        self.sys_health_card.grid_columnconfigure(1, weight=1)

        self.sys_score_badge = ctk.CTkLabel(
            self.sys_health_card,
            text=" 100% ",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            fg_color="#dcfce7",
            text_color="#166534",
            corner_radius=10,
            width=90,
            height=48
        )
        self.sys_score_badge.grid(row=0, column=0, rowspan=2, padx=18, pady=16)

        self.sys_health_title = ctk.CTkLabel(
            self.sys_health_card,
            text=t("sys_health_default", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color="#0f172a"
        )
        self.sys_health_title.grid(row=0, column=1, padx=0, pady=(16, 2), sticky="w")

        self.sys_health_desc = ctk.CTkLabel(
            self.sys_health_card,
            text=t("sys_health_desc_default", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#64748b"
        )
        self.sys_health_desc.grid(row=1, column=1, padx=0, pady=(0, 16), sticky="w")

        self.btn_quick_ask_ai_sys = ctk.CTkButton(
            self.sys_health_card,
            text=t("btn_ask_ai_sys", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=34,
            corner_radius=8,
            command=lambda: self.go_to_chat_with_prompt(
                "How is my PC health according to the scan? Are there any processes to handle or watch out for?" if self.language == "en" else "ผลสแกนเครื่องคอมพิวเตอร์เป็นอย่างไรบ้าง มีโปรแกรมไหนที่ควรจัดการหรือระวังไหม?"
            )
        )
        self.btn_quick_ask_ai_sys.grid(row=0, column=2, rowspan=2, padx=18, pady=16, sticky="e")
        self.btn_quick_ask_ai_sys.grid_remove()

        # 4-Pillar Security Cards
        pillar_frame = ctk.CTkFrame(self.sys_scroll, fg_color="transparent")
        pillar_frame.pack(fill="x", pady=(0, 12))
        pillar_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.sm1 = self._create_metric_box(pillar_frame, 0, t("sm_processes", self.language), "0", "#0284c7")
        self.sm2 = self._create_metric_box(pillar_frame, 1, t("sm_startup", self.language), "0", "#6366f1")
        self.sm3 = self._create_metric_box(pillar_frame, 2, t("sm_temp", self.language), "0", "#d97706")
        self.sm4 = self._create_metric_box(pillar_frame, 3, t("sm_network", self.language), "0", "#10b981")

        # Findings Container
        self.findings_container = ctk.CTkFrame(self.sys_scroll, corner_radius=14, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        self.findings_container.pack(fill="x", pady=(0, 10))
        self.findings_container.grid_columnconfigure(0, weight=1)

        self.findings_header = ctk.CTkLabel(
            self.findings_container,
            text=t("findings_header", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color="#0f172a"
        )
        self.findings_header.pack(anchor="w", padx=18, pady=(14, 8))

        self.findings_list_frame = ctk.CTkFrame(self.findings_container, fg_color="transparent")
        self.findings_list_frame.pack(fill="x", padx=14, pady=(0, 14))
        self.findings_list_frame.grid_columnconfigure(0, weight=1)

        self.findings_placeholder_lbl = ctk.CTkLabel(
            self.findings_list_frame,
            text=t("findings_placeholder", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#64748b"
        )
        self.findings_placeholder_lbl.pack(pady=10)

    # =========================================================================
    # VIEW 3: REAL-TIME SHIELD
    # =========================================================================
    def _build_realtime_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(2, weight=1)
        self.view_frames["realtime"] = view

        hero_card = ctk.CTkFrame(view, corner_radius=14, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        hero_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        hero_card.grid_columnconfigure(1, weight=1)

        shield_icon = ctk.CTkLabel(hero_card, text="🛡️", font=ctk.CTkFont(size=28))
        shield_icon.grid(row=0, column=0, rowspan=2, padx=18, pady=16)

        self.rt_status_title = ctk.CTkLabel(
            hero_card,
            text=t("rt_active_title", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color="#166534"
        )
        self.rt_status_title.grid(row=0, column=1, padx=0, pady=(16, 2), sticky="w")

        self.rt_status_desc = ctk.CTkLabel(
            hero_card,
            text=t("rt_active_desc", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#64748b"
        )
        self.rt_status_desc.grid(row=1, column=1, padx=0, pady=(0, 16), sticky="w")

        self.rt_main_switch = ctk.CTkSwitch(
            hero_card,
            text=t("rt_switch_lbl", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#0f172a",
            progress_color="#10b981",
            command=self._on_realtime_main_toggle
        )
        self.rt_main_switch.grid(row=0, column=2, rowspan=2, padx=20, pady=16, sticky="e")
        if self.realtime_enabled:
            self.rt_main_switch.select()
        else:
            self.rt_main_switch.deselect()

        stats_frame = ctk.CTkFrame(view, fg_color="transparent")
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.rt_m1 = self._create_metric_box(stats_frame, 0, t("rt_metric_total", self.language), "0", "#0284c7")
        self.rt_m2 = self._create_metric_box(stats_frame, 1, t("rt_metric_clean", self.language), "0", "#10b981")
        self.rt_m3 = self._create_metric_box(stats_frame, 2, t("rt_metric_danger", self.language), "0", "#ef4444")

        stream_container = ctk.CTkFrame(view, corner_radius=14, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        stream_container.grid(row=2, column=0, sticky="nsew")
        stream_container.grid_columnconfigure(0, weight=1)
        stream_container.grid_rowconfigure(1, weight=1)

        stream_top = ctk.CTkFrame(stream_container, fg_color="transparent")
        stream_top.grid(row=0, column=0, sticky="ew", padx=16, pady=12)
        stream_top.grid_columnconfigure(0, weight=1)

        self.rt_stream_title = ctk.CTkLabel(
            stream_top,
            text=t("rt_stream_title", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#0f172a"
        )
        self.rt_stream_title.grid(row=0, column=0, sticky="w")

        self.btn_clear_stream = ctk.CTkButton(
            stream_top,
            text=t("btn_clear", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#f1f5f9",
            hover_color="#fee2e2",
            text_color="#64748b",
            border_width=1,
            border_color="#cbd5e1",
            height=28,
            width=110,
            corner_radius=6,
            command=self._clear_realtime_stream
        )
        self.btn_clear_stream.grid(row=0, column=1, sticky="e")

        self.rt_stream_scroll = ctk.CTkScrollableFrame(stream_container, fg_color="transparent")
        self.rt_stream_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.rt_stream_scroll.grid_columnconfigure(0, weight=1)

        self._render_realtime_stream()

    def _on_realtime_main_toggle(self):
        self.realtime_enabled = bool(self.rt_main_switch.get())
        save_config(self.vt_api_key, self.gemini_api_key, self.auto_quarantine, self.realtime_enabled, self.start_with_windows, self.language)
        
        if self.realtime_enabled:
            self._start_realtime_guard()
            self.rt_status_title.configure(text=t("rt_active_title", self.language), text_color="#166534")
            self.rt_status_desc.configure(text=t("rt_active_desc", self.language))
        else:
            self.realtime_guard.stop()
            self.rt_status_title.configure(text=t("rt_paused_title", self.language), text_color="#64748b")
            self.rt_status_desc.configure(text=t("rt_paused_desc", self.language))

    def _clear_realtime_stream(self):
        self.realtime_events = []
        self._render_realtime_stream()

    def _render_realtime_stream(self):
        for widget in self.rt_stream_scroll.winfo_children():
            widget.destroy()

        unit_str = " files" if self.language == "en" else " ไฟล์"
        times_str = " times" if self.language == "en" else " ครั้ง"
        self.rt_m1.configure(text=f"{self.rt_total_count}{unit_str}")
        self.rt_m2.configure(text=f"{self.rt_clean_count}{unit_str}")
        self.rt_m3.configure(text=f"{self.rt_danger_count}{times_str}")

        if not self.realtime_events:
            empty_box = ctk.CTkFrame(self.rt_stream_scroll, corner_radius=10, fg_color="#f8fafc", border_width=1, border_color="#e2e8f0")
            empty_box.pack(fill="x", pady=10)
            lbl = ctk.CTkLabel(
                empty_box,
                text=t("rt_stream_placeholder", self.language),
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color="#64748b"
            )
            lbl.pack(padx=16, pady=16)
        else:
            for event in self.realtime_events[:30]:
                self._render_single_realtime_card(event)

    def _render_single_realtime_card(self, event):
        risk = event["overall_risk"]
        if risk == "DANGER":
            card_bg = "#fef2f2"
            border_c = "#fecaca"
            badge_bg = "#fee2e2"
            badge_fg = "#991b1b"
            badge_icon = "🚨 Threat" if self.language == "en" else "🚨 ภัยคุกคามอันตราย"
        elif risk == "WARNING":
            card_bg = "#fffbeb"
            border_c = "#fde68a"
            badge_bg = "#fef3c7"
            badge_fg = "#92400e"
            badge_icon = "⚠️ Warning" if self.language == "en" else "⚠️ ควรระมัดระวัง"
        else:
            card_bg = "#f0fdf4"
            border_c = "#bbf7d0"
            badge_bg = "#dcfce7"
            badge_fg = "#166534"
            badge_icon = "🟢 Safe" if self.language == "en" else "🟢 ปลอดภัย"

        card = ctk.CTkFrame(self.rt_stream_scroll, corner_radius=10, fg_color=card_bg, border_width=1, border_color=border_c)
        card.pack(fill="x", pady=4)
        card.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkLabel(
            card,
            text=f" {badge_icon} ",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color=badge_bg,
            text_color=badge_fg,
            corner_radius=6
        )
        badge.grid(row=0, column=0, padx=12, pady=10, sticky="nw")

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=0, pady=10, sticky="ew")
        info_frame.grid_columnconfigure(0, weight=1)

        q_note = (" 🔒 [Quarantined]" if self.language == "en" else " 🔒 [ย้ายเข้าห้องกักกันเรียบร้อยแล้ว]") if event.get("is_quarantined") else ""
        name_lbl = ctk.CTkLabel(
            info_frame,
            text=f"[{event['timestamp']}]  {event['file_name']}  ({event.get('size_mb', 0)} MB){q_note}",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#0f172a"
        )
        name_lbl.pack(anchor="w")

        ev_lbl = "• Event: " if self.language == "en" else "• เหตุการณ์: "
        res_lbl = "\n• Summary: " if self.language == "en" else "\n• สรุปผล: "
        desc_lbl = ctk.CTkLabel(
            info_frame,
            text=f"{ev_lbl}{event['event_type']}{res_lbl}{event['ai_summary']}",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#475569",
            wraplength=600,
            justify="left"
        )
        desc_lbl.pack(anchor="w", pady=(2, 0))

    # =========================================================================
    # VIEW 4: QUARANTINE VAULT
    # =========================================================================
    def _build_quarantine_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)
        self.view_frames["quarantine"] = view

        q_top = ctk.CTkFrame(view, corner_radius=12, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        q_top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        q_top.grid_columnconfigure(0, weight=1)

        self.q_count_lbl = ctk.CTkLabel(
            q_top,
            text=t("quarantine_header", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#0f172a"
        )
        self.q_count_lbl.grid(row=0, column=0, padx=18, pady=12, sticky="w")

        btn_frame = ctk.CTkFrame(q_top, fg_color="transparent")
        btn_frame.grid(row=0, column=1, padx=14, pady=12, sticky="e")

        self.btn_refresh_q = ctk.CTkButton(
            btn_frame,
            text=t("btn_refresh", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#f1f5f9",
            hover_color="#e2e8f0",
            text_color="#0f172a",
            border_width=1,
            border_color="#cbd5e1",
            height=32,
            width=120,
            corner_radius=8,
            command=self.refresh_quarantine_list
        )
        self.btn_refresh_q.pack(side="left", padx=(0, 8))

        self.btn_delete_all_q = ctk.CTkButton(
            btn_frame,
            text=t("btn_delete_all", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#fee2e2",
            hover_color="#fecaca",
            text_color="#991b1b",
            border_width=1,
            border_color="#f87171",
            height=32,
            width=150,
            corner_radius=8,
            command=self._handle_delete_all
        )
        self.btn_delete_all_q.pack(side="left")

        self.q_scroll = ctk.CTkScrollableFrame(view, fg_color="transparent")
        self.q_scroll.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.q_scroll.grid_columnconfigure(0, weight=1)

    def refresh_quarantine_list(self):
        for widget in self.q_scroll.winfo_children():
            widget.destroy()

        items = list_quarantined_files()
        self.q_count_lbl.configure(text=t("quarantine_count", self.language, count=len(items)))
        self.btn_refresh_q.configure(text=t("btn_refresh", self.language))
        self.btn_delete_all_q.configure(
            text=t("btn_delete_all", self.language),
            state="normal" if items else "disabled"
        )

        if "quarantine" in self.nav_buttons:
            badge_txt = t("nav_quarantine", self.language) + (f" [{len(items)}]" if len(items) > 0 else "")
            self.nav_buttons["quarantine"].configure(text=badge_txt)

        if not items:
            empty_card = ctk.CTkFrame(self.q_scroll, corner_radius=12, fg_color="#f0fdf4", border_width=1, border_color="#bbf7d0")
            empty_card.pack(fill="x", pady=10)
            lbl = ctk.CTkLabel(
                empty_card,
                text=t("quarantine_empty", self.language),
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color="#166534"
            )
            lbl.pack(padx=20, pady=16)
        else:
            for item in items:
                self._render_quarantine_item(item)

    def _render_quarantine_item(self, item):
        card = ctk.CTkFrame(self.q_scroll, corner_radius=12, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        card.pack(fill="x", pady=6)
        card.grid_columnconfigure(1, weight=1)

        icon_lbl = ctk.CTkLabel(
            card,
            text="🔒",
            font=ctk.CTkFont(size=20),
            width=40,
            height=40,
            fg_color="#fee2e2",
            corner_radius=10
        )
        icon_lbl.grid(row=0, column=0, padx=14, pady=14, sticky="nw")

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=0, pady=14, sticky="ew")
        info_frame.grid_columnconfigure(0, weight=1)

        name_lbl = ctk.CTkLabel(
            info_frame,
            text=f"{item['file_name']}  ({item.get('size_mb', 0)} MB)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#0f172a"
        )
        name_lbl.pack(anchor="w")

        rs_lbl = "• Reason: " if self.language == "en" else "• สาเหตุ: "
        dt_lbl = "\n• Date: " if self.language == "en" else "\n• วันที่กักกัน: "
        og_lbl = "\n• Original Path: " if self.language == "en" else "\n• ตำแหน่งเดิม: "

        desc_lbl = ctk.CTkLabel(
            info_frame,
            text=f"{rs_lbl}{item['threat_reason']}{dt_lbl}{item['quarantine_date']}{og_lbl}{item['original_path']}",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#64748b",
            wraplength=520,
            justify="left"
        )
        desc_lbl.pack(anchor="w", pady=(2, 0))

        act_frame = ctk.CTkFrame(card, fg_color="transparent")
        act_frame.grid(row=0, column=2, padx=14, pady=14, sticky="e")

        btn_restore = ctk.CTkButton(
            act_frame,
            text=t("btn_restore", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=32,
            width=130,
            corner_radius=8,
            command=lambda i_id=item["id"]: self._handle_restore(i_id)
        )
        btn_restore.pack(pady=(0, 6))

        btn_del = ctk.CTkButton(
            act_frame,
            text=t("btn_delete", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#fee2e2",
            hover_color="#fecaca",
            text_color="#991b1b",
            height=30,
            width=130,
            corner_radius=8,
            command=lambda i_id=item["id"]: self._handle_delete(i_id)
        )
        btn_del.pack()

    def _handle_restore(self, item_id):
        confirm_title = "Confirm File Restoration" if self.language == "en" else "ยืนยันการกู้คืนไฟล์"
        confirm_msg = "Are you sure you want to restore this file back to its original location?" if self.language == "en" else "คุณแน่ใจหรือไม่ว่าต้องการกู้คืนไฟล์นี้กลับไปยังตำแหน่งเดิม?"
        if messagebox.askyesno(confirm_title, confirm_msg):
            res = restore_file(item_id)
            if res["success"]:
                messagebox.showinfo("Success" if self.language == "en" else "สำเร็จ", res["message"])
                self.refresh_quarantine_list()
            else:
                messagebox.showerror("Error" if self.language == "en" else "เกิดข้อผิดพลาด", res["error"])

    def _handle_delete(self, item_id):
        confirm_title = "Confirm Permanent Deletion" if self.language == "en" else "ยืนยันการลบไฟล์ถาวร"
        confirm_msg = "Warning: The file will be permanently erased and cannot be recovered.\n\nAre you sure?" if self.language == "en" else "คำเตือน: ไฟล์จะถูกลบออกจากเครื่องอย่างถาวรและไม่สามารถกู้คืนได้\n\nคุณแน่ใจหรือไม่?"
        if messagebox.askyesno(confirm_title, confirm_msg):
            res = delete_quarantined_file(item_id)
            if res["success"]:
                messagebox.showinfo("Success" if self.language == "en" else "สำเร็จ", res["message"])
                self.refresh_quarantine_list()
            else:
                messagebox.showerror("Error" if self.language == "en" else "เกิดข้อผิดพลาด", res["error"])

    def _handle_delete_all(self):
        items = list_quarantined_files()
        if not items:
            empty_title = "Quarantine" if self.language == "en" else "ห้องกักกันนิรภัย"
            empty_msg = "No files in quarantine." if self.language == "en" else "ไม่มีไฟล์ในห้องกักกัน"
            messagebox.showinfo(empty_title, empty_msg)
            return

        confirm_title = t("confirm_delete_all_title", self.language)
        confirm_msg = t("confirm_delete_all_msg", self.language, count=len(items))

        if messagebox.askyesno(confirm_title, confirm_msg):
            res = delete_all_quarantined_files()
            if res.get("success"):
                deleted_count = res.get("deleted_count", 0)
                succ_title = "Success" if self.language == "en" else "สำเร็จ"
                succ_msg = (
                    f"Successfully deleted all {deleted_count} quarantined files permanently!"
                    if self.language == "en" else
                    f"ลบไฟล์ทั้งหมดจำนวน {deleted_count} รายการ ออกจากเครื่องอย่างถาวรเรียบร้อยแล้ว!"
                )
                messagebox.showinfo(succ_title, succ_msg)
                self.refresh_quarantine_list()
                self._append_log(f"🗑️ Deleted all {deleted_count} quarantined files permanently.")
            else:
                err_title = "Error" if self.language == "en" else "เกิดข้อผิดพลาด"
                messagebox.showerror(err_title, res.get("error", "Failed to delete files"))

    # =========================================================================
    # VIEW 5: GEMINI CHAT
    # =========================================================================
    def _build_chat_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)
        self.view_frames["chat"] = view

        chat_top_bar = ctk.CTkFrame(view, fg_color="transparent")
        chat_top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        chat_top_bar.grid_columnconfigure(0, weight=1)

        self.chat_assistant_info = ctk.CTkLabel(
            chat_top_bar,
            text=t("chat_assistant_info", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#0284c7"
        )
        self.chat_assistant_info.grid(row=0, column=0, sticky="w")

        self.btn_clear_chat = ctk.CTkButton(
            chat_top_bar,
            text=t("btn_clear", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#ffffff",
            hover_color="#fee2e2",
            text_color="#64748b",
            border_width=1,
            border_color="#cbd5e1",
            height=28,
            width=110,
            corner_radius=6,
            command=self.clear_chat
        )
        self.btn_clear_chat.grid(row=0, column=1, sticky="e")

        self.chat_scroll = ctk.CTkScrollableFrame(
            view,
            corner_radius=12,
            fg_color="#ffffff",
            border_width=1,
            border_color="#e2e8f0"
        )
        self.chat_scroll.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        self.chat_scroll.grid_columnconfigure(0, weight=1)

        chips_frame = ctk.CTkFrame(view, fg_color="transparent")
        chips_frame.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        
        self.chip_label = ctk.CTkLabel(chips_frame, text=t("chip_label", self.language), font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#64748b")
        self.chip_label.pack(side="left", padx=(0, 8))

        self.chip_btn_1 = ctk.CTkButton(
            chips_frame,
            text=t("chip_1", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#ffffff",
            hover_color="#e0f2fe",
            text_color="#0369a1",
            border_width=1,
            border_color="#bae6fd",
            height=26,
            corner_radius=13,
            command=lambda: self.send_chip_prompt(t("chip_1", self.language))
        )
        self.chip_btn_1.pack(side="left", padx=4)

        self.chip_btn_2 = ctk.CTkButton(
            chips_frame,
            text=t("chip_2", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#ffffff",
            hover_color="#e0f2fe",
            text_color="#0369a1",
            border_width=1,
            border_color="#bae6fd",
            height=26,
            corner_radius=13,
            command=lambda: self.send_chip_prompt(t("chip_2", self.language))
        )
        self.chip_btn_2.pack(side="left", padx=4)

        self.chip_btn_3 = ctk.CTkButton(
            chips_frame,
            text=t("chip_3", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#ffffff",
            hover_color="#e0f2fe",
            text_color="#0369a1",
            border_width=1,
            border_color="#bae6fd",
            height=26,
            corner_radius=13,
            command=lambda: self.send_chip_prompt(t("chip_3", self.language))
        )
        self.chip_btn_3.pack(side="left", padx=4)

        input_container = ctk.CTkFrame(view, fg_color="transparent")
        input_container.grid(row=3, column=0, sticky="ew", pady=(0, 4))
        input_container.grid_columnconfigure(0, weight=1)

        self.chat_input = ctk.CTkEntry(
            input_container,
            placeholder_text=t("chat_placeholder", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=40,
            corner_radius=20,
            fg_color="#ffffff",
            border_color="#cbd5e1"
        )
        self.chat_input.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.chat_input.bind("<Return>", lambda event: self.send_chat_message())

        self.btn_send_chat = ctk.CTkButton(
            input_container,
            text=t("btn_send", self.language),
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=40,
            corner_radius=20,
            width=120,
            command=self.send_chat_message
        )
        self.btn_send_chat.grid(row=0, column=1)

        self._add_ai_bubble(t("chat_welcome", self.language))

    def _add_user_bubble(self, message_text: str):
        row_frame = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        row_frame.pack(fill="x", pady=6, padx=8)
        row_frame.grid_columnconfigure(0, weight=1)

        bubble = ctk.CTkFrame(row_frame, fg_color="#0284c7", corner_radius=14)
        bubble.pack(side="right", anchor="e")

        msg_lbl = ctk.CTkLabel(
            bubble,
            text=message_text,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#ffffff",
            wraplength=580,
            justify="left"
        )
        msg_lbl.pack(padx=14, pady=10)
        self.after(50, lambda: self.chat_scroll._parent_canvas.yview_moveto(1.0))

    def _add_ai_bubble(self, message_text: str):
        row_frame = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        row_frame.pack(fill="x", pady=6, padx=8)

        avatar = ctk.CTkLabel(
            row_frame,
            text="✨",
            font=ctk.CTkFont(size=16),
            width=32,
            height=32,
            fg_color="#e0f2fe",
            corner_radius=16
        )
        avatar.pack(side="left", anchor="n", padx=(0, 8), pady=2)

        bubble = ctk.CTkFrame(row_frame, fg_color="#f8fafc", corner_radius=14, border_width=1, border_color="#e2e8f0")
        bubble.pack(side="left", anchor="w")

        msg_lbl = ctk.CTkLabel(
            bubble,
            text=message_text,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#0f172a",
            wraplength=620,
            justify="left"
        )
        msg_lbl.pack(padx=16, pady=12)
        self.after(50, lambda: self.chat_scroll._parent_canvas.yview_moveto(1.0))

    def _show_thinking_indicator(self):
        if self.thinking_card is not None:
            return
        self.thinking_card = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        self.thinking_card.pack(fill="x", pady=6, padx=8)

        avatar = ctk.CTkLabel(self.thinking_card, text="✨", font=ctk.CTkFont(size=16), width=32, height=32, fg_color="#e0f2fe", corner_radius=16)
        avatar.pack(side="left", anchor="n", padx=(0, 8), pady=2)

        bubble = ctk.CTkFrame(self.thinking_card, fg_color="#f1f5f9", corner_radius=14, border_width=1, border_color="#e2e8f0")
        bubble.pack(side="left", anchor="w")

        thinking_txt = "⏳ Gemini is analyzing and typing response..." if self.language == "en" else "⏳ Gemini กำลังวิเคราะห์และพิมพ์คำตอบ..."
        lbl = ctk.CTkLabel(bubble, text=thinking_txt, font=ctk.CTkFont(family="Segoe UI", size=12, slant="italic"), text_color="#64748b")
        lbl.pack(padx=16, pady=10)
        self.after(50, lambda: self.chat_scroll._parent_canvas.yview_moveto(1.0))

    def _hide_thinking_indicator(self):
        if self.thinking_card is not None:
            self.thinking_card.destroy()
            self.thinking_card = None

    def clear_chat(self):
        for widget in self.chat_scroll.winfo_children():
            widget.destroy()
        self.chat_history = []
        self.thinking_card = None
        self._add_ai_bubble(t("chat_cleared", self.language))

    def send_chip_prompt(self, prompt_text: str):
        self.chat_input.delete(0, "end")
        self.chat_input.insert(0, prompt_text)
        self.send_chat_message()

    # =========================================================================
    # VIEW 6: TECHNICAL LOG
    # =========================================================================
    def _build_log_view(self):
        view = ctk.CTkFrame(self.views_container, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(0, weight=1)
        self.view_frames["log"] = view

        self.log_textbox = ctk.CTkTextbox(
            view,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            fg_color="#0f172a",
            text_color="#f8fafc",
            border_width=1,
            border_color="#334155",
            corner_radius=12
        )
        self.log_textbox.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.log_textbox.insert("end", "[*] CyberGuard AI Ready - Real-Time Shield Active...\n")

    # =========================================================================
    # COMMON WIDGET HELPERS
    # =========================================================================
    def _create_metric_box(self, parent, col, title, initial_val, color):
        box = ctk.CTkFrame(parent, corner_radius=10, fg_color="#ffffff", border_width=1, border_color="#e2e8f0")
        box.grid(row=0, column=col, padx=4, pady=0, sticky="nsew")
        box.grid_columnconfigure(0, weight=1)

        lbl_title = ctk.CTkLabel(box, text=title, font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"), text_color="#64748b")
        lbl_title.pack(anchor="w", padx=14, pady=(10, 2))

        lbl_val = ctk.CTkLabel(box, text=initial_val, font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"), text_color=color)
        lbl_val.pack(anchor="w", padx=14, pady=(0, 10))
        
        lbl_val.title_label = lbl_title
        return lbl_val

    def _create_check_row(self, parent, title, initial_val):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=4)
        row.grid_columnconfigure(1, weight=1)

        lbl_t = ctk.CTkLabel(row, text=title, font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"), text_color="#334155", width=280, anchor="w")
        lbl_t.grid(row=0, column=0, sticky="w")

        lbl_v = ctk.CTkLabel(row, text=initial_val, font=ctk.CTkFont(family="Segoe UI", size=12), text_color="#64748b", anchor="w")
        lbl_v.grid(row=0, column=1, sticky="w")
        
        lbl_v.title_label = lbl_t
        return lbl_v

    def _append_log(self, text: str):
        self.log_textbox.insert("end", text + "\n")
        self.log_textbox.see("end")

    # =========================================================================
    # LOGIC: SETTINGS
    # =========================================================================
    def open_settings(self):
        ApiSettingsDialog(
            self,
            self.vt_api_key,
            self.gemini_api_key,
            self.auto_quarantine,
            self.realtime_enabled,
            self.start_with_windows,
            self.language,
            self._on_settings_saved
        )

    def _on_settings_saved(self, vt_k, gm_k, auto_q, rt_en, boot_en, lang):
        self.vt_api_key = vt_k
        self.gemini_api_key = gm_k
        self.auto_quarantine = auto_q
        self.realtime_enabled = rt_en
        self.start_with_windows = boot_en
        old_lang = self.language
        self.language = lang

        if auto_q:
            self.sidebar_auto_switch.select()
        else:
            self.sidebar_auto_switch.deselect()

        if rt_en:
            self.rt_main_switch.select()
            self._start_realtime_guard()
        else:
            self.rt_main_switch.deselect()
            self.realtime_guard.stop()

        if old_lang != lang:
            self.apply_language(lang)

        messagebox.showinfo(t("settings_dialog_title", self.language), t("saved_msg", self.language))

    # =========================================================================
    # LOGIC: FILE SCAN
    # =========================================================================
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File for Security Inspection" if self.language == "en" else "เลือกไฟล์สำหรับวิเคราะห์ความปลอดภัย",
            filetypes=[
                ("All Files", "*.*"),
                ("Executables (*.exe, *.dll, *.bat, *.ps1)", "*.exe;*.dll;*.bat;*.ps1;*.scr;*.vbs"),
                ("Documents (*.pdf, *.docx, *.xlsx, *.zip)", "*.pdf;*.docx;*.xlsx;*.zip")
            ]
        )
        if file_path:
            self.selected_file_path = os.path.abspath(file_path)
            self.path_entry.configure(state="normal")
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, self.selected_file_path)
            self.path_entry.configure(state="readonly")

            self.btn_file_scan.configure(state="normal")
            self.file_risk_lbl.configure(
                text=t("risk_selected", self.language, name=os.path.basename(self.selected_file_path)),
                text_color="#0284c7"
            )
            self.btn_quick_ask_ai_file.grid_remove()
            self.btn_manual_quarantine.grid_remove()

    def start_file_scan_thread(self):
        if not self.selected_file_path or self.is_file_scanning:
            return

        self.is_file_scanning = True
        self.btn_browse.configure(state="disabled")
        self.btn_file_scan.configure(state="disabled")
        self.btn_quick_ask_ai_file.grid_remove()
        self.btn_manual_quarantine.grid_remove()
        self.file_progress.start()

        self.file_risk_lbl.configure(text=t("risk_scanning", self.language), text_color="#d97706")
        self.file_ai_summary.configure(text=t("ai_processing", self.language))

        scan_thread = threading.Thread(target=self._run_file_scan_worker, daemon=True)
        scan_thread.start()

    def _run_file_scan_worker(self):
        try:
            results = scan_file(
                file_path=self.selected_file_path,
                vt_api_key=self.vt_api_key,
                gemini_api_key=self.gemini_api_key,
                auto_quarantine=self.auto_quarantine,
                lang=self.language
            )
            self.after(0, self._handle_file_scan_complete, results)
        except Exception as e:
            err = {"success": False, "error": str(e), "file_name": os.path.basename(self.selected_file_path)}
            self.after(0, self._handle_file_scan_complete, err)

    def _handle_file_scan_complete(self, results):
        self.file_progress.stop()
        self.file_progress.set(1.0)
        self.btn_browse.configure(state="normal")
        self.btn_file_scan.configure(state="normal")
        self.is_file_scanning = False

        if not results.get("success", False):
            err_msg = results.get("error", "Unknown scan error")
            self.file_risk_lbl.configure(text=f"❌ Error: {err_msg}", text_color="#ef4444")
            messagebox.showerror("Error", err_msg)
            return

        self.current_file_result = results
        self.chat_history = []

        is_quarantined = bool(results.get("quarantine_info") and results["quarantine_info"].get("success"))
        q_msg = ""
        if is_quarantined:
            q_msg = (" [🛡️ Quarantined]" if self.language == "en" else " [🛡️ ย้ายเข้าห้องกักกันนิรภัยเรียบร้อยแล้ว]")
            self.refresh_quarantine_list()

        self.file_risk_card.configure(
            fg_color=results["risk_badge_bg"],
            border_color=results["risk_badge_border"]
        )
        lbl_risk_prefix = "Risk Level: " if self.language == "en" else "ระดับความเสี่ยง: "
        self.file_risk_lbl.configure(
            text=f"{lbl_risk_prefix}{results['risk_label']}{q_msg}",
            text_color=results["risk_badge_text"]
        )

        target_file_path = results.get("file_path") or self.selected_file_path
        if is_quarantined:
            self.btn_manual_quarantine.configure(
                text=t("btn_already_quarantined", self.language),
                state="disabled",
                fg_color="#94a3b8"
            )
            self.btn_manual_quarantine.grid()
        elif target_file_path and os.path.exists(target_file_path):
            self.btn_manual_quarantine.configure(
                text=t("btn_manual_quarantine", self.language),
                state="normal",
                fg_color="#dc2626"
            )
            self.btn_manual_quarantine.grid()
        else:
            self.btn_manual_quarantine.grid_remove()

        self.btn_quick_ask_ai_file.grid()

        self.file_ai_summary.configure(text=results["ai_summary"])
        if results.get("overall_risk") == "DANGER":
            self.file_ai_card.configure(fg_color="#fef2f2", border_color="#fecaca")
        elif results.get("overall_risk") == "WARNING":
            self.file_ai_card.configure(fg_color="#fffbeb", border_color="#fde68a")
        else:
            self.file_ai_card.configure(fg_color="#f0fdf4", border_color="#bbf7d0")

        self.fm1.configure(text=f"{results['file_size_mb']:.2f} MB")
        self.fm2.configure(text=f"{results['entropy']} / 8.0")
        
        vt_mal = results["vt_result"].get("malicious", 0)
        vt_clean = results["vt_result"].get("harmless", 0) + results["vt_result"].get("undetected", 0)
        engine_unit = " engines" if self.language == "en" else " ค่าย"
        self.fm3.configure(text=f"{vt_mal}{engine_unit}" if results["vt_result"]["available"] else "Local Mode")
        self.fm4.configure(text=f"{vt_clean}{engine_unit}" if results["vt_result"]["available"] else "Local Mode")

        mb = results["magic_bytes"]
        if self.language == "en":
            mb_text = "🚨 Extension Spoofing Detected!" if mb["is_spoofed"] else "✅ Valid File Header"
        else:
            mb_text = "🚨 ตรวจพบการปลอมนามสกุล!" if mb["is_spoofed"] else "✅ ถูกต้องตามมาตรฐาน"
        self.chk_magic.configure(text=mb_text, text_color="#dc2626" if mb["is_spoofed"] else "#16a34a")

        dext = results["double_ext"]
        if self.language == "en":
            dext_text = f"🚨 Dangerous Double Ext ({dext['ext_chain']})" if dext["is_dangerous"] else ("⚠️ Double Extension" if dext["is_double_ext"] else "✅ Single Normal Extension")
        else:
            dext_text = f"🚨 ซ้อนนามสกุลอันตราย ({dext['ext_chain']})" if dext["is_dangerous"] else ("⚠️ ซ้อนนามสกุล" if dext["is_double_ext"] else "✅ นามสกุลเดี่ยวปกติ")
        self.chk_dext.configure(text=dext_text, text_color="#dc2626" if dext["is_dangerous"] else ("#d97706" if dext["is_double_ext"] else "#16a34a"))

        ent = results["entropy_risk"]
        self.chk_entropy.configure(
            text=f"⚠️ {ent['description']}" if ent["is_suspicious"] else f"✅ {ent['description']}",
            text_color="#d97706" if ent["is_suspicious"] else "#16a34a"
        )

        pe = results["pe_analysis"]
        if pe["is_pe"]:
            if pe.get("has_critical_apis"):
                apis_hint = ", ".join([a.split()[0] for a in pe.get("dangerous_apis", [])[:2]])
                pe_txt = f"🚨 Dangerous Win32 APIs ({apis_hint})" if self.language == "en" else f"🚨 ตรวจพบ Windows APIs อันตราย ({apis_hint})"
                pe_color = "#dc2626"
            elif pe.get("has_wx_sections"):
                pe_txt = "🚨 WX Section (Write+Execute Shellcode)" if self.language == "en" else "🚨 พบ Section สิทธิ์ WX (Write+Execute)"
                pe_color = "#dc2626"
            elif pe["has_suspicious_sections"] or pe.get("is_packed"):
                pe_txt = f"⚠️ {len(pe['suspicious_sections'])} Packed Sections (Entropy > 7.5)" if self.language == "en" else f"⚠️ พบ {len(pe['suspicious_sections'])} Section ที่มี Entropy > 7.5 (Packer)"
                pe_color = "#d97706"
            elif pe.get("dangerous_apis"):
                pe_txt = f"⚠️ Suspicious APIs ({len(pe['dangerous_apis'])})" if self.language == "en" else f"⚠️ พบการเรียก API ที่ควรระวัง ({len(pe['dangerous_apis'])} รายการ)"
                pe_color = "#d97706"
            else:
                pe_txt = f"✅ Normal ({len(pe['all_sections'])} Sections)" if self.language == "en" else f"✅ โครงสร้างและ API ปกติ ({len(pe['all_sections'])} Sections)"
                pe_color = "#16a34a"
            self.chk_pe.configure(text=pe_txt, text_color=pe_color)
        else:
            self.chk_pe.configure(text="ℹ️ Non-Executable File" if self.language == "en" else "ℹ️ ไม่ใช่ไฟล์ Executable Binary", text_color="#64748b")

        st_res = results["strings_analysis"]
        if st_res["found_commands"]:
            cmd_prefix = "🚨 Detected: " if self.language == "en" else "🚨 ตรวจพบคำสั่ง: "
            self.chk_strings.configure(text=f"{cmd_prefix}{', '.join(st_res['found_commands'][:3])}", text_color="#dc2626")
        elif st_res["has_network_indicators"]:
            self.chk_strings.configure(text="⚠️ Embedded URL / IP" if self.language == "en" else "⚠️ พบ URL / IP แอบแฝงในไฟล์", text_color="#d97706")
        else:
            self.chk_strings.configure(text="✅ Clean (No suspicious commands)" if self.language == "en" else "✅ ไม่พบคำสั่งระบบหรือ URL อันตราย", text_color="#16a34a")

        # Update YARA Checklist Row
        y_res = results.get("yara_result", {})
        if y_res.get("matched"):
            y_rules = ", ".join([m["rule"] for m in y_res.get("matches", [])[:2]])
            det_prefix = "🚨 Match (" if self.language == "en" else "🚨 ตรวจพบ ("
            self.chk_yara.configure(text=f"{det_prefix}{y_rules})", text_color="#dc2626")
        elif y_res.get("available", False):
            self.chk_yara.configure(text="✅ Clean (No YARA matches)" if self.language == "en" else "✅ ปลอดภัย (ไม่พบในฐานข้อมูล YARA)", text_color="#16a34a")
        else:
            self.chk_yara.configure(text="⚪ Unavailable" if self.language == "en" else "⚪ ไม่พร้อมใช้งาน", text_color="#64748b")

        self._append_log(f"=== Scan Complete: {results['file_name']} ===")
        self._append_log(f"Size: {results['file_size_mb']:.2f} MB | SHA-256: {results['sha256']}")
        self._append_log(f"Status: {results['risk_label']} | Entropy: {results['entropy']}/8.0\n")

        bubble_msg = (
            f"Scanned '{results['file_name']}' successfully! ✨\nRisk Assessment: {results['risk_label']}{q_msg}\nYou can click 'Ask AI about this file' or ask questions below!"
            if self.language == "en" else
            f"สแกนไฟล์ '{results['file_name']}' เรียบร้อยแล้วครับ! ✨\nผลการประเมิน: {results['risk_label']}{q_msg}\nคุณสามารถคลิกปุ่ม '💬 ถาม AI เกี่ยวกับไฟล์นี้' หรือพิมพ์คำถามที่ช่องด้านล่างได้เลยครับ"
        )
        self._add_ai_bubble(bubble_msg)

    def manual_quarantine_current_file(self):
        if not self.current_file_result:
            return

        target_path = self.current_file_result.get("file_path") or self.selected_file_path
        if not target_path or not os.path.exists(target_path):
            err_txt = "File does not exist or has already been moved." if self.language == "en" else "ไม่พบไฟล์ หรือไฟล์อาจถูกย้ายไปแล้ว"
            messagebox.showerror("Error" if self.language == "en" else "ข้อผิดพลาด", err_txt)
            self.btn_manual_quarantine.grid_remove()
            return

        file_name = os.path.basename(target_path)
        confirm_title = t("confirm_quarantine_title", self.language)
        confirm_msg = t("confirm_quarantine_msg", self.language, name=file_name)

        if not messagebox.askyesno(confirm_title, confirm_msg):
            return

        threat_reason = f"Manual Quarantine ({self.current_file_result.get('risk_label', 'User Action')})"
        q_res = quarantine_file(target_path, threat_reason=threat_reason)

        if q_res.get("success"):
            self.current_file_result["quarantine_info"] = q_res
            self.refresh_quarantine_list()
            self.btn_manual_quarantine.configure(
                text=t("btn_already_quarantined", self.language),
                state="disabled",
                fg_color="#94a3b8"
            )
            lbl_risk_prefix = "Risk Level: " if self.language == "en" else "ระดับความเสี่ยง: "
            q_msg = " [🛡️ Quarantined]" if self.language == "en" else " [🛡️ ย้ายเข้าห้องกักกันนิรภัยเรียบร้อยแล้ว]"
            self.file_risk_lbl.configure(
                text=f"{lbl_risk_prefix}{self.current_file_result.get('risk_label', '')}{q_msg}"
            )
            success_msg = t("quarantine_success", self.language, name=file_name)
            messagebox.showinfo("Success" if self.language == "en" else "สำเร็จ", success_msg)
            self._append_log(f"🛡️ File '{file_name}' manually moved to Quarantine Vault.")

            ai_note = (
                f"File '{file_name}' has been safely locked and moved to the Quarantine Vault."
                if self.language == "en" else
                f"ล็อกและย้ายไฟล์ '{file_name}' เข้าห้องกักกันนิรภัย (Quarantine Vault) เรียบร้อยแล้วครับ ปลอดภัยแน่นอน!"
            )
            self._add_ai_bubble(ai_note)
        else:
            err_msg = q_res.get("error", "Failed to quarantine file")
            messagebox.showerror("Error" if self.language == "en" else "ข้อผิดพลาด", err_msg)

    # =========================================================================
    # LOGIC: SYSTEM SECURITY SCAN
    # =========================================================================
    def start_system_scan_thread(self):
        if self.is_system_scanning:
            return

        self.is_system_scanning = True
        self.btn_sys_scan.configure(state="disabled")
        self.btn_quick_ask_ai_sys.grid_remove()
        self.sys_progress.set(0.1)

        self.sys_status_lbl.configure(text=t("sys_status_scanning", self.language), text_color="#d97706")

        sys_thread = threading.Thread(target=self._run_system_scan_worker, daemon=True)
        sys_thread.start()

    def _run_system_scan_worker(self):
        def on_progress(msg, prog_val):
            self.after(0, self._update_sys_progress, msg, prog_val)

        try:
            results = run_full_system_scan(progress_callback=on_progress, auto_quarantine=self.auto_quarantine)
            self.after(0, self._handle_system_scan_complete, results)
        except Exception as e:
            err = {"error": str(e)}
            self.after(0, self._handle_system_scan_complete, err)

    def _update_sys_progress(self, msg, prog_val):
        self.sys_status_lbl.configure(text=f"🔍 {msg}", text_color="#0284c7")
        self.sys_progress.set(prog_val)

    def _handle_system_scan_complete(self, results):
        self.btn_sys_scan.configure(state="normal")
        self.is_system_scanning = False
        self.sys_progress.set(1.0)

        if "error" in results:
            err_msg = results["error"]
            self.sys_status_lbl.configure(text=f"❌ Error: {err_msg}", text_color="#ef4444")
            messagebox.showerror("Error", err_msg)
            return

        self.current_system_result = results

        score = results["score"]
        status_label = results["status_label"]
        status_color = results["status_color"]

        if score >= 90:
            badge_bg = "#dcfce7"
            badge_fg = "#166534"
        elif score >= 75:
            badge_bg = "#fef3c7"
            badge_fg = "#92400e"
        else:
            badge_bg = "#fee2e2"
            badge_fg = "#991b1b"

        self.sys_score_badge.configure(text=f" {score}% ", fg_color=badge_bg, text_color=badge_fg)
        status_prefix = "System Status: " if self.language == "en" else "สถานะระบบ: "
        self.sys_health_title.configure(text=f"{status_prefix}{status_label}", text_color=status_color)
        self.sys_health_desc.configure(text=results["summary_msg"])
        done_msg = f"✅ System audit completed! (Health Score: {score}%)" if self.language == "en" else f"✅ สแกนระบบเสร็จสมบูรณ์! (คะแนนสุขภาพ: {score}%)"
        self.sys_status_lbl.configure(text=done_msg, text_color="#16a34a")

        self.btn_quick_ask_ai_sys.grid()

        proc_stats = results["process_stats"]
        startup_stats = results["startup_stats"]
        temp_stats = results["temp_stats"]
        net_stats = results["network_stats"]

        proc_unit = " processes" if self.language == "en" else " โปรเซส"
        item_unit = " items" if self.language == "en" else " รายการ"
        file_unit = " files" if self.language == "en" else " ไฟล์"
        conn_unit = " connections" if self.language == "en" else " การเชื่อมต่อ"

        self.sm1.configure(text=f"{proc_stats['total_scanned']}{proc_unit}")
        self.sm2.configure(text=f"{startup_stats['total_startup_items']}{item_unit}")
        self.sm3.configure(text=f"{temp_stats['total_temp_scanned']}{file_unit}")
        self.sm4.configure(text=f"{net_stats['total_connections']}{conn_unit}")

        for widget in self.findings_list_frame.winfo_children():
            widget.destroy()

        findings = results["findings"]
        if not findings:
            clean_card = ctk.CTkFrame(self.findings_list_frame, corner_radius=10, fg_color="#f0fdf4", border_width=1, border_color="#bbf7d0")
            clean_card.pack(fill="x", pady=4)
            lbl = ctk.CTkLabel(
                clean_card,
                text="🎉 Excellent! No malware, rogue processes, or suspicious startup items found." if self.language == "en" else "🎉 ยอดเยี่ยม! ไม่พบมัลแวร์, โปรเซสแปลกปลอม, หรือรายการ Startup ที่น่าสงสัยภายในเครื่องของคุณ",
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                text_color="#166534"
            )
            lbl.pack(padx=16, pady=12)
        else:
            for item in findings:
                self._render_finding_item(item)

        if results.get("auto_actions_taken"):
            self.refresh_quarantine_list()

        self._append_log(f"=== System Security Audit Complete ===")
        self._append_log(f"Health Score: {score}% | {status_label}")
        self._append_log(f"Processes: {proc_stats['total_scanned']} | Startup: {startup_stats['total_startup_items']} | Network: {net_stats['total_connections']}")
        self._append_log(f"Findings: {len(findings)} items\n")

        chat_sys_msg = (
            f"System security audit completed! 🖥️✨\nHealth Score: {score}%\nStatus: {status_label}\nSummary: {results['summary_msg']}\n\nYou can consult AI on next steps or ask questions anytime!"
            if self.language == "en" else
            f"สแกนความปลอดภัยระบบเครื่องเสร็จเรียบร้อยครับ! 🖥️✨\nคะแนนสุขภาพระบบ: {score}%\nสถานะ: {status_label}\nสรุป: {results['summary_msg']}\n\nคุณสามารถคลิกปุ่ม '💬 ปรึกษา AI เกี่ยวกับระบบเครื่อง' หรือถามข้อสงสัยได้เลยครับ!"
        )
        self._add_ai_bubble(chat_sys_msg)

    def _render_finding_item(self, item):
        risk = item["risk_level"]
        if risk == "DANGER":
            card_bg = "#fef2f2"
            border_c = "#fecaca"
            badge_bg = "#fee2e2"
            badge_fg = "#991b1b"
            badge_txt = "🚨 Danger" if self.language == "en" else "🚨 อันตราย (Danger)"
        elif risk == "WARNING":
            card_bg = "#fffbeb"
            border_c = "#fde68a"
            badge_bg = "#fef3c7"
            badge_fg = "#92400e"
            badge_txt = "⚠️ Warning" if self.language == "en" else "⚠️ ควรระวัง (Warning)"
        else:
            card_bg = "#f8fafc"
            border_c = "#e2e8f0"
            badge_bg = "#e0f2fe"
            badge_fg = "#0369a1"
            badge_txt = "ℹ️ Info" if self.language == "en" else "ℹ️ ข้อมูล (Info)"

        card = ctk.CTkFrame(self.findings_list_frame, corner_radius=10, fg_color=card_bg, border_width=1, border_color=border_c)
        card.pack(fill="x", pady=4)
        card.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkLabel(
            card,
            text=f" {badge_txt} ",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color=badge_bg,
            text_color=badge_fg,
            corner_radius=6
        )
        badge.grid(row=0, column=0, padx=12, pady=10, sticky="nw")

        content_frame = ctk.CTkFrame(card, fg_color="transparent")
        content_frame.grid(row=0, column=1, padx=(0, 12), pady=10, sticky="ew")
        content_frame.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            content_frame,
            text=f"[{item['category']}] {item['title']}",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#0f172a"
        )
        title_lbl.pack(anchor="w")

        dtl_lbl = "• Details: " if self.language == "en" else "• รายละเอียด: "
        pth_lbl = "\n• Path/Cmd: " if self.language == "en" else "\n• ตำแหน่ง/คำสั่ง: "
        detail_lbl = ctk.CTkLabel(
            content_frame,
            text=f"{dtl_lbl}{item['detail']}{pth_lbl}{item['path']}",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#475569",
            wraplength=600,
            justify="left"
        )
        detail_lbl.pack(anchor="w", pady=(2, 0))

    # =========================================================================
    # LOGIC: CHATBOT
    # =========================================================================
    def send_chat_message(self):
        user_text = self.chat_input.get().strip()
        if not user_text:
            return

        active_context = {}
        if self.current_file_result:
            active_context = self.current_file_result
        elif self.current_system_result:
            active_context = {
                "file_name": "System Security Audit" if self.language == "en" else "ผลการสแกนระบบคอมพิวเตอร์",
                "file_size_mb": 0,
                "sha256": "N/A (System Scan)",
                "overall_risk": self.current_system_result["status_label"],
                "entropy": 0,
                "pe_analysis": {"suspicious_sections": []},
                "strings_analysis": {"found_commands": []},
                "magic_bytes": {"message": "N/A"},
                "vt_result": {"malicious": 0, "suspicious": 0},
                "ai_summary": f"Health Score: {self.current_system_result['score']}% - {self.current_system_result['summary_msg']}"
            }
        else:
            active_context = {
                "file_name": "General Computer" if self.language == "en" else "คอมพิวเตอร์ทั่วไป",
                "file_size_mb": 0,
                "sha256": "N/A",
                "overall_risk": "SAFE",
                "entropy": 0,
                "pe_analysis": {"suspicious_sections": []},
                "strings_analysis": {"found_commands": []},
                "magic_bytes": {"message": "N/A"},
                "vt_result": {"malicious": 0, "suspicious": 0},
                "ai_summary": "Ready to assist with cybersecurity analysis." if self.language == "en" else "พร้อมให้คำปรึกษาด้านความปลอดภัยไซเบอร์และตรวจสอบคอมพิวเตอร์"
            }

        self.chat_input.delete(0, "end")
        self._add_user_bubble(user_text)
        self._show_thinking_indicator()
        self.btn_send_chat.configure(state="disabled")

        chat_thread = threading.Thread(
            target=self._run_chat_worker,
            args=(user_text, active_context),
            daemon=True
        )
        chat_thread.start()

    def _run_chat_worker(self, user_text, context):
        try:
            ai_reply = ask_gemini_chat(
                file_context=context,
                chat_history=self.chat_history,
                user_question=user_text,
                api_key=self.gemini_api_key,
                lang=self.language
            )
            self.chat_history.append({"role": "user", "text": user_text})
            self.chat_history.append({"role": "assistant", "text": ai_reply})
            self.after(0, self._handle_chat_reply, ai_reply)
        except Exception as e:
            self.after(0, self._handle_chat_reply, f"⚠️ Error: {str(e)}")

    def _handle_chat_reply(self, reply_text):
        self._hide_thinking_indicator()
        self.btn_send_chat.configure(state="normal")
        self._add_ai_bubble(reply_text)


if __name__ == "__main__":
    app = MalwareScannerApp()
    app.mainloop()
