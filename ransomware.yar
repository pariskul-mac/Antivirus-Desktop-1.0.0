/*
   CyberGuard AI - Ransomware Detection Rules
   Targets destructive behavior: Shadow copy deletion, Boot recovery disablement, Ransom notes, and encryption indicators.
*/

rule Detect_Ransomware_ShadowCopy_Wiper {
    meta:
        description = "ตรวจจับคำสั่งทำลาย Shadow Copy และ Backup เพื่อขัดขวางการกู้คืนข้อมูล (Ransomware Behavior)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "vssadmin.exe delete shadows" nocase
        $s3 = "wmic shadowcopy delete" nocase
        $s4 = "wbadmin delete catalog" nocase
        $s5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $s6 = "bcdedit /set {default} recoveryenabled no" nocase
    condition:
        any of ($s*)
}

rule Detect_Ransomware_Note_Indicators {
    meta:
        description = "ตรวจจับข้อความและรูปแบบข้อความเรียกค่าไถ่ (Ransom Note)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $r1 = "All your files have been encrypted" nocase
        $r2 = "pay the ransom" nocase
        $r3 = "Your personal ID for decryption" nocase
        $r4 = "decrypt your files" nocase
        $r5 = "TOR browser" nocase
        $r6 = ".onion" nocase
        $r7 = "bitcoin" nocase
    condition:
        2 of ($r*)
}
