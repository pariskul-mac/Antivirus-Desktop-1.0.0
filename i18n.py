# Localization Module for CyberGuard AI Pro (Thai & English)

TRANSLATIONS = {
    "th": {
        # App branding
        "app_title": "CyberGuard AI",
        "app_sub": "PRO EDITION v3.5",
        "status_ready": "🟢  ระบบพร้อมปกป้อง 100%",
        "nav_section": "เมนูการทำงานหลัก",
        
        # Sidebar
        "nav_file_scan": "📁  สแกนไฟล์เดี่ยว",
        "nav_system_scan": "🖥️  สแกนระบบเครื่อง",
        "nav_realtime": "🛡️  เฝ้าระวังเรียลไทม์",
        "nav_quarantine": "🔒  ห้องกักกันนิรภัย",
        "nav_chat": "💬  ผู้ช่วย Gemini AI",
        "nav_log": "📜  บันทึกทางเทคนิค",
        "sidebar_auto_title": "⚡ Auto-Defense Mode",
        "sidebar_auto_switch": "เปิดทำงานทันที",
        "sidebar_settings_btn": "⚙️  ตั้งค่า",

        # Header Titles
        "title_file_scan": "📁  สแกนและวิเคราะห์ไฟล์เดี่ยว (File Threat Analysis)",
        "title_system_scan": "🖥️  สแกนความปลอดภัยทั้งระบบคอมพิวเตอร์ (System Security Audit)",
        "title_realtime": "🛡️  ระบบเฝ้าระวังแบบเรียลไทม์ (Real-Time Active Shield)",
        "title_quarantine": "🔒  ห้องกักกันนิรภัย (Quarantine Vault)",
        "title_chat": "💬  ผู้ช่วย AI ด้านความปลอดภัยไซเบอร์ (Gemini Cyber Assistant)",
        "title_log": "📜  บันทึกเหตุการณ์และข้อมูลทางเทคนิค (Technical Logs)",

        # File Scanner
        "btn_browse": "📂 เลือกไฟล์ (Browse)",
        "placeholder_path": "กรุณาเลือกไฟล์สำหรับสแกน (รองรับไฟล์ขนาดสูงสุด 500 MB)...",
        "btn_start_file_scan": "🚀 เริ่มสแกนไฟล์ (Scan)",
        "risk_ready": "🛡️ สถานะความเสี่ยงภาพรวม: พร้อมสแกน",
        "risk_selected": "📁 เลือกไฟล์แล้ว: {name} (กด 'เริ่มสแกนไฟล์' เพื่อวิเคราะห์)",
        "risk_scanning": "🔍 กำลังสแกนโครงสร้าง Magic Bytes, Section Entropy, และเรียกข้อมูล AI...",
        "ai_processing": "⏳ กำลังประมวลผลข้อมูลและวิเคราะห์ความปลอดภัย...",
        "btn_ask_ai_file": "💬 ถาม AI เกี่ยวกับไฟล์นี้ ➡️",
        "btn_manual_quarantine": "🛡️ ย้ายเข้าห้องกักกัน",
        "btn_already_quarantined": "🛡️ กักกันแล้ว",
        "confirm_quarantine_title": "ยืนยันการกักกันไฟล์",
        "confirm_quarantine_msg": "คุณต้องการย้ายและล็อกไฟล์ '{name}' เข้าห้องกักกันนิรภัย (Quarantine Vault) ใช่หรือไม่?\n\nไฟล์จะถูกระงับสิทธิ์การทำงานและแยกเก็บอย่างปลอดภัย",
        "quarantine_success": "ย้ายไฟล์ '{name}' เข้าห้องกักกันนิรภัยเรียบร้อยแล้ว!",
        "file_ai_card_header": "⚡ สรุปผลด่วนเข้าใจง่าย (Security Executive Summary)",
        "file_ai_placeholder": "กรุณาเลือกไฟล์แล้วกดปุ่ม 'เริ่มสแกนไฟล์' เพื่อรับบทวิเคราะห์และสรุปผลความปลอดภัย",
        "metric_size": "📏 ขนาดไฟล์",
        "metric_entropy": "🌀 ความซับซ้อน (Entropy)",
        "metric_vt_detected": "🚨 VirusTotal ตรวจพบ",
        "metric_vt_clean": "🟢 Antivirus ยืนยันปลอดภัย",
        "chk_title": "🔍 รายการตรวจสอบความปลอดภัย 6 ด้านหลัก (Security Checklist)",
        "chk_magic_lbl": "1. Magic Bytes (ปลอมแปลงนามสกุล):",
        "chk_dext_lbl": "2. Double Extension (นามสกุลซ้อน):",
        "chk_entropy_lbl": "3. File Entropy (ความซับซ้อนของข้อมูล):",
        "chk_pe_lbl": "4. PE Section (>7.5 Packer/Crypt):",
        "chk_strings_lbl": "5. Embedded Text & Base64 Commands:",
        "chk_yara_lbl": "6. YARA Signatures (กฎลายนิ้วมือมัลแวร์):",
        "chk_not_scanned": "ยังไม่ได้สแกน",

        # System Scanner
        "btn_start_sys_scan": "🚀 เริ่มสแกนความปลอดภัยเครื่อง (Scan My PC)",
        "sys_status_ready": "พร้อมสแกน • ตรวจสอบ Running Processes, Startup Autorun, และไฟล์ตกค้างในเครื่อง",
        "sys_status_scanning": "⏳ กำลังเริ่มต้นสแกนความปลอดภัยทั้งระบบ...",
        "sys_health_default": "คะแนนสุขภาพและความปลอดภัยระบบ: ยังไม่ได้สแกน",
        "sys_health_desc_default": "กดปุ่ม 'เริ่มสแกนความปลอดภัยเครื่อง' ด้านบนเพื่อเริ่มต้นตรวจสอบ 4 เสาหลักของระบบปฏิบัติการ",
        "btn_ask_ai_sys": "💬 ปรึกษา AI เกี่ยวกับระบบเครื่อง ➡️",
        "sm_processes": "⚙️ Running Processes",
        "sm_startup": "🚀 Startup Autorun",
        "sm_temp": "📁 Temp & AppData Files",
        "sm_network": "🌐 Active Connections",
        "findings_header": "📋 รายการตรวจพบและความผิดปกติในเครื่อง (Security Findings)",
        "findings_placeholder": "⚪ ยังไม่มีข้อมูลการสแกนระบบ (กด 'เริ่มสแกนความปลอดภัยเครื่อง' เพื่อเริ่มต้น)",

        # Real-Time Shield
        "rt_active_title": "ระบบเฝ้าระวังเรียลไทม์: 🟢 ทำงานอยู่ (Active Protection)",
        "rt_active_desc": "ระบบกำลังเฝ้าระวังโฟลเดอร์ Downloads, Desktop และตรวจจับแฟลชไดรฟ์ (USB) อัตโนมัติในพื้นหลัง",
        "rt_paused_title": "ระบบเฝ้าระวังเรียลไทม์: ⚪ ปิดการทำงานชั่วคราว (Paused)",
        "rt_paused_desc": "ระบบหยุดเฝ้าระวังไฟล์ใหม่อัตโนมัติชั่วคราว (คุณยังสามารถกดสแกนไฟล์เองได้ปกติ)",
        "rt_switch_lbl": "เปิด Real-Time Guard",
        "rt_metric_total": "📁 สแกนไฟล์ใหม่อัตโนมัติ",
        "rt_metric_clean": "🟢 ไฟล์สะอาดปลอดภัย",
        "rt_metric_danger": "🚨 ภัยคุกคามที่กักกันทันที",
        "rt_stream_title": "📡 กิจกรรมการเฝ้าระวังแบบเรียลไทม์ (Live Security Stream)",
        "rt_stream_placeholder": "📡 กำลังเฝ้าระวัง... เมื่อคุณดาวน์โหลดไฟล์ใหม่หรือเสียบ Flash Drive กิจกรรมจะปรากฏขึ้นที่นี่อัตโนมัติ",
        "btn_clear": "🗑️ ล้างประวัติ (Clear)",

        # Quarantine
        "quarantine_header": "🔒 ห้องกักกันนิรภัย (Quarantine Vault) • ตัดสิทธิ์การทำงานของไฟล์อันตรายอย่างปลอดภัย",
        "quarantine_count": "🔒 ห้องกักกันนิรภัย (Quarantine Vault) • พบไฟล์กักกันจำนวน {count} รายการ",
        "quarantine_empty": "✨ ห้องกักกันว่างเปล่า ไม่มีไฟล์อันตรายหรือไฟล์ที่ถูกล็อคกักกันอยู่ในระบบ",
        "btn_refresh": "🔄 รีเฟรชรายการ",
        "btn_restore": "🔄 กู้คืน (Restore)",
        "btn_delete": "🗑️ ลบถาวร (Delete)",
        "btn_delete_all": "🗑️ ลบทั้งหมด (Delete All)",
        "confirm_delete_all_title": "ยืนยันการลบไฟล์ทั้งหมด",
        "confirm_delete_all_msg": "คุณแน่ใจหรือไม่ว่าต้องการลบไฟล์ทั้งหมดจำนวน {count} รายการ ออกจากห้องกักกันอย่างถาวร?\n\n(ไฟล์จะถูกลบทิ้งอย่างถาวรและไม่สามารถกู้คืนได้)",

        # Chat
        "chat_assistant_info": "✨ Gemini Cyber Assistant (พร้อมให้คำปรึกษาตลอด 24 ชม.)",
        "chat_placeholder": "พิมพ์ข้อความถาม Gemini เกี่ยวกับไฟล์หรือระบบเครื่อง (กด Enter เพื่อส่ง)...",
        "btn_send": "ส่ง (Send) 🚀",
        "chip_label": "💡 คำถามแนะนำ:",
        "chip_1": "ไฟล์ที่เพิ่งสแกนปลอดภัยไหม?",
        "chip_2": "ผลสแกนเครื่องพบสิ่งผิดปกติไหม แก้ไขอย่างไร?",
        "chip_3": "ทำไมต้องเฝ้าระวังโฟลเดอร์ Downloads?",
        "chat_welcome": "สวัสดีครับ! ผมคือ Gemini Cybersecurity Assistant ✨\nคุณสามารถสแกนไฟล์เดี่ยว, สแกนความปลอดภัยเครื่องทั้งระบบ หรือตรวจสอบเหตุการณ์ Real-Time Shield แล้วมาพิมพ์สอบถามความเสี่ยงและวิธีแก้ปัญหาได้ที่นี่เลยครับ!",
        "chat_cleared": "🗑️ ล้างประวัติแชตเรียบร้อยครับ พร้อมตอบคำถามใหม่เกี่ยวกับไฟล์หรือระบบเครื่องแล้วครับ!",

        # Settings Dialog
        "settings_dialog_title": "⚙️ ตั้งค่า (Settings)",
        "settings_dialog_header": "⚙️ ตั้งค่าระบบ (Settings & Preferences)",
        "settings_dialog_desc": "เลือกภาษาการแสดงผล, ตั้งค่า API Keys และกำหนดการทำงานอัตโนมัติของระบบ",
        "lbl_language": "🌐 ภาษาของระบบ (Language):",
        "lbl_vt_key": "VirusTotal API Key:",
        "lbl_gemini_key": "Google Gemini AI API Key:",
        "ph_vt_key": "วาง VirusTotal API Key ที่นี่...",
        "ph_gemini_key": "วาง Gemini API Key ที่นี่...",
        "switch_realtime": "🛡️ เปิดระบบเฝ้าระวังแบบเรียลไทม์ (Real-Time Downloads & USB Guard)",
        "switch_auto_defense": "⚡ เปิดโหมดจัดการอัตโนมัติ (Auto-Quarantine & Kill Process ทันที)",
        "switch_boot": "🚀 เปิดโปรแกรมอัตโนมัติพร้อมเริ่ม Windows (Start on Windows Boot)",
        "btn_open_yara": "📂 เปิดโฟลเดอร์กฎ YARA",
        "btn_save": "💾 บันทึกการตั้งค่า (Save)",
        "btn_cancel": "ยกเลิก",
        "saved_msg": "บันทึกการตั้งค่าเรียบร้อยแล้ว ระบบจะนำไปใช้ทันที",
    },

    "en": {
        # App branding
        "app_title": "CyberGuard AI",
        "app_sub": "PRO EDITION v3.5",
        "status_ready": "🟢  System Protected 100%",
        "nav_section": "MAIN NAVIGATION",
        
        # Sidebar
        "nav_file_scan": "📁  File Threat Scanner",
        "nav_system_scan": "🖥️  System Security Audit",
        "nav_realtime": "🛡️  Real-Time Shield",
        "nav_quarantine": "🔒  Quarantine Vault",
        "nav_chat": "💬  Gemini AI Assistant",
        "nav_log": "📜  Technical Logs",
        "sidebar_auto_title": "⚡ Auto-Defense Mode",
        "sidebar_auto_switch": "Active Protection",
        "sidebar_settings_btn": "⚙️  Settings",

        # Header Titles
        "title_file_scan": "📁  Single File Threat & Behavior Analysis",
        "title_system_scan": "🖥️  Comprehensive Operating System Security Audit",
        "title_realtime": "🛡️  Real-Time Active Shield & USB Guard",
        "title_quarantine": "🔒  Quarantine Vault (Isolated Files)",
        "title_chat": "💬  Gemini Cybersecurity AI Assistant",
        "title_log": "📜  Technical Events & Diagnostics Log",

        # File Scanner
        "btn_browse": "📂 Browse File",
        "placeholder_path": "Select a file for deep security inspection (up to 500 MB)...",
        "btn_start_file_scan": "🚀 Start Scan",
        "risk_ready": "🛡️ Overall Risk Status: Ready to scan",
        "risk_selected": "📁 File selected: {name} (Click 'Start Scan' to analyze)",
        "risk_scanning": "🔍 Inspecting Magic Bytes, PE Section Entropy, and YARA signatures...",
        "ai_processing": "⏳ Evaluating security telemetry and AI synthesis...",
        "btn_ask_ai_file": "💬 Ask AI about this file ➡️",
        "btn_manual_quarantine": "🛡️ Move to Quarantine",
        "btn_already_quarantined": "🛡️ Quarantined",
        "confirm_quarantine_title": "Confirm Quarantine",
        "confirm_quarantine_msg": "Are you sure you want to isolate and lock '{name}' into the Quarantine Vault?\n\nExecution permissions will be safely stripped.",
        "quarantine_success": "File '{name}' has been safely moved to Quarantine Vault!",
        "file_ai_card_header": "⚡ Security Executive Summary",
        "file_ai_placeholder": "Please select a file and click 'Start Scan' to generate real-time AI security analysis.",
        "metric_size": "📏 File Size",
        "metric_entropy": "🌀 Shannon Entropy",
        "metric_vt_detected": "🚨 VirusTotal Detected",
        "metric_vt_clean": "🟢 Antivirus Verified Clean",
        "chk_title": "🔍 6-Pillar Security Inspection Checklist",
        "chk_magic_lbl": "1. Magic Bytes (Extension Spoofing):",
        "chk_dext_lbl": "2. Double Extension Disguise:",
        "chk_entropy_lbl": "3. File Entropy (Obfuscation / Packing):",
        "chk_pe_lbl": "4. PE Section (>7.5 Packed/Encrypted):",
        "chk_strings_lbl": "5. Embedded Text & Base64 Commands:",
        "chk_yara_lbl": "6. YARA Signatures (Malware DNA):",
        "chk_not_scanned": "Not yet scanned",

        # System Scanner
        "btn_start_sys_scan": "🚀 Scan My PC",
        "sys_status_ready": "Ready • Auditing running processes, startup autorun, and temporary directories",
        "sys_status_scanning": "⏳ Performing full system security audit...",
        "sys_health_default": "System Health & Security Score: Not yet audited",
        "sys_health_desc_default": "Click 'Scan My PC' above to inspect the 4 core pillars of your operating system.",
        "btn_ask_ai_sys": "💬 Consult AI on PC Health ➡️",
        "sm_processes": "⚙️ Running Processes",
        "sm_startup": "🚀 Startup Autorun",
        "sm_temp": "📁 Temp & AppData Files",
        "sm_network": "🌐 Active Connections",
        "findings_header": "📋 Detected Anomalies & Security Findings",
        "findings_placeholder": "⚪ No system scan results yet (Click 'Scan My PC' to initiate)",

        # Real-Time Shield
        "rt_active_title": "Real-Time Shield: 🟢 Active Protection",
        "rt_active_desc": "Actively monitoring Downloads, Desktop, and removable USB storage drives in the background.",
        "rt_paused_title": "Real-Time Shield: ⚪ Temporarily Paused",
        "rt_paused_desc": "Real-time download surveillance is paused (Manual file scanning is still available).",
        "rt_switch_lbl": "Enable Real-Time Guard",
        "rt_metric_total": "📁 Auto-Scanned Files",
        "rt_metric_clean": "🟢 Clean & Harmless",
        "rt_metric_danger": "🚨 Quarantined Threats",
        "rt_stream_title": "📡 Live Real-Time Security Event Stream",
        "rt_stream_placeholder": "📡 Active monitoring... Newly downloaded files or plugged USB drives will appear here automatically.",
        "btn_clear": "🗑️ Clear Stream",

        # Quarantine
        "quarantine_header": "🔒 Quarantine Vault • Malicious files safely isolated and disarmed",
        "quarantine_count": "🔒 Quarantine Vault • {count} file(s) safely isolated",
        "quarantine_empty": "✨ Vault is empty. No threats or quarantined files found in your system.",
        "btn_refresh": "🔄 Refresh List",
        "btn_restore": "🔄 Restore",
        "btn_delete": "🗑️ Permanently Delete",
        "btn_delete_all": "🗑️ Delete All",
        "confirm_delete_all_title": "Confirm Delete All",
        "confirm_delete_all_msg": "Are you sure you want to permanently delete all {count} quarantined files?\n\n(Files will be deleted permanently and cannot be recovered)",

        # Chat
        "chat_assistant_info": "✨ Gemini Cyber Assistant (Available 24/7)",
        "chat_placeholder": "Ask Gemini about files, threats, or PC health (Press Enter to send)...",
        "btn_send": "Send 🚀",
        "chip_label": "💡 Suggested:",
        "chip_1": "Is the recently scanned file safe?",
        "chip_2": "Any anomalies found on my PC? How to fix?",
        "chip_3": "Why is monitoring the Downloads folder important?",
        "chat_welcome": "Hello! I am your Gemini Cybersecurity Assistant ✨\nYou can scan files, perform full PC audits, or inspect Real-Time Shield events, and ask me questions anytime!",
        "chat_cleared": "🗑️ Chat history cleared. Ready for your questions!",

        # Settings Dialog
        "settings_dialog_title": "⚙️ Settings",
        "settings_dialog_header": "⚙️ System Settings & Preferences",
        "settings_dialog_desc": "Configure display language, cloud API keys, and automatic defense features.",
        "lbl_language": "🌐 Interface Language:",
        "lbl_vt_key": "VirusTotal API Key:",
        "lbl_gemini_key": "Google Gemini AI API Key:",
        "ph_vt_key": "Paste VirusTotal API Key here...",
        "ph_gemini_key": "Paste Gemini API Key here...",
        "switch_realtime": "🛡️ Real-Time Shield (Surveillance for Downloads & USB)",
        "switch_auto_defense": "⚡ Auto-Defense Mode (Auto-Quarantine threats & Kill dangerous processes)",
        "switch_boot": "🚀 Start with Windows (Launch in background on boot)",
        "btn_open_yara": "📂 Open YARA Rules Folder",
        "btn_save": "💾 Save Settings",
        "btn_cancel": "Cancel",
        "saved_msg": "Settings saved successfully and applied immediately.",
    }
}


def t(key: str, lang: str = "th", **kwargs) -> str:
    """Translates key to target language. Falls back to Thai if key not found in English."""
    dict_lang = TRANSLATIONS.get(lang, TRANSLATIONS["th"])
    val = dict_lang.get(key, TRANSLATIONS["th"].get(key, key))
    if kwargs:
        try:
            return val.format(**kwargs)
        except Exception:
            pass
    return val
