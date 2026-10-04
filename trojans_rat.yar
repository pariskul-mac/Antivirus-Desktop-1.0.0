/*
   CyberGuard AI - High-Fidelity Trojan, RAT & Ransomware Rules
   Covers major real-world malware families: AsyncRAT, AgentTesla, RedLine, WannaCry, XWorm, and Injection Stubs.
*/

rule Detect_AsyncRAT_Family {
    meta:
        description = "ตรวจจับม้าโทรจันควบคุมเครื่องระยะไกลตระกูล AsyncRAT (Remote Access Trojan)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $a1 = "AsyncRAT" ascii wide nocase
        $a2 = "AsyncClient" ascii wide
        $a3 = "Stub.exe" ascii wide
        $a4 = "Select * from Win32_ComputerSystem" ascii wide
        $a5 = "\\AsyncRAT\\Stub\\" ascii wide nocase
        $a6 = "Pastebin" ascii wide nocase
        $a7 = "Server.exe" ascii wide nocase
    condition:
        2 of ($a*)
}

rule Detect_AgentTesla_Infostealer {
    meta:
        description = "ตรวจจับมัลแวร์ขโมยรหัสผ่านและคุกกี้ระบบตระกูล AgentTesla (Infostealer)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $t1 = "AgentTesla" ascii wide nocase
        $t2 = "get_Keyboard" ascii wide
        $t3 = "GetClipboardData" ascii wide
        $t4 = "ImeSelectedFiles" ascii wide
        $t5 = "webcam" ascii wide nocase
        $t6 = "smtp.gmail.com" ascii wide nocase
        $t7 = "Account" ascii wide
        $t8 = "Recovered" ascii wide
    condition:
        3 of ($t*)
}

rule Detect_RedLine_Stealer {
    meta:
        description = "ตรวจจับมัลแวร์ขโมยกระเป๋าเงินคริปโตและรหัสผ่านตระกูล RedLine Stealer"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $r1 = "RedLine.Client" ascii wide nocase
        $r2 = "CommandLineUpdate" ascii wide
        $r3 = "ScanningArgs" ascii wide
        $r4 = "DownloadAndExecuteUpdate" ascii wide
        $r5 = "Chrome_GetPasswords" ascii wide nocase
        $r6 = "Telegram_Session" ascii wide nocase
    condition:
        2 of ($r*)
}

rule Detect_WannaCry_Ransomware {
    meta:
        description = "ตรวจจับแรนซัมแวร์เรียกค่าไถ่ WannaCry / WanaCrypt0r 2.0"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $w1 = "WANACRY!" ascii
        $w2 = "WanaCrypt0r" ascii wide nocase
        $w3 = "tasksche.exe" ascii wide nocase
        $w4 = "mssecsvc.exe" ascii wide nocase
        $w5 = "taskse.exe" ascii wide nocase
        $w6 = ".wnry" ascii wide nocase
        $w7 = "attrib +h ." ascii wide nocase
    condition:
        2 of ($w*)
}

rule Detect_XWorm_RAT {
    meta:
        description = "ตรวจจับม้าโทรจันและบ็อตเน็ตตระกูล XWorm"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $x1 = "XWorm" ascii wide nocase
        $x2 = "XClient" ascii wide
        $x3 = "XLogger" ascii wide
        $x4 = "XWorm V" ascii wide nocase
        $x5 = "XWorm RAT" ascii wide nocase
    condition:
        2 of ($x*)
}

rule Detect_Generic_Process_Injection_Routine {
    meta:
        description = "ตรวจจับพฤติกรรม Process Injection และ Memory Hollowing เพื่อแอบรันโค้ดลับในโปรแกรมอื่น"
        author = "CyberGuard AI"
        severity = "WARNING"
    strings:
        $i1 = "VirtualAllocEx" ascii wide
        $i2 = "WriteProcessMemory" ascii wide
        $i3 = "CreateRemoteThread" ascii wide
        $i4 = "QueueUserAPC" ascii wide
        $i5 = "NtUnmapViewOfSection" ascii wide
        $i6 = "SetThreadContext" ascii wide
    condition:
        3 of ($i*)
}

rule Detect_Generic_Ransomware_Extensions_Note {
    meta:
        description = "ตรวจจับพฤติกรรมไฟล์เรียกค่าไถ่สากล (Generic Ransomware)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $rn1 = "HOW_TO_RECOVER_FILES" ascii wide nocase
        $rn2 = "RESTORE_FILES_INFO" ascii wide nocase
        $rn3 = "README_DECRYPT" ascii wide nocase
        $rn4 = "Your network is compromised" ascii wide nocase
        $rn5 = "All documents, photos, databases were encrypted" ascii wide nocase
        $rn6 = "bitcoin address" ascii wide nocase
    condition:
        2 of ($rn*)
}
