/*
   CyberGuard AI - Hacktools & Exploit Frameworks Detection Rules
   Targets: Mimikatz, Reverse Shells, AMSI Bypass, Meterpreter/Cobalt Strike.
*/

rule Detect_Mimikatz_LSASS_Dumping {
    meta:
        description = "ตรวจจับเครื่องมือเจาะระบบและขโมยรหัสผ่านหน่วยความจำ LSASS (Mimikatz)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "privilege::debug" nocase
        $m4 = "gentilkiwi" nocase
        $m5 = "sekurlsa::wdigest" nocase
    condition:
        any of ($m*)
}

rule Detect_PowerShell_AMSI_Bypass {
    meta:
        description = "ตรวจจับเทคนิคการปิดกั้นและบายพาสระบบตรวจจับ Windows Defender / AMSI (AMSI Bypass)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $a1 = "AmsiUtils" nocase
        $a2 = "amsiInitFailed" nocase
        $a3 = "NonPublic,Static" nocase
        $a4 = "GetField('amsiSession'" nocase
    condition:
        2 of ($a*)
}

rule Detect_Reverse_Shell_Cradle {
    meta:
        description = "ตรวจจับคำสั่งเปิด Reverse Shell หรือดาวน์โหลด Payload รันสดในหน่วยความจำ"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $c1 = "DownloadString" nocase
        $c2 = "IEX" nocase
        $c3 = "Invoke-Expression" nocase
        $c4 = "System.Net.Sockets.TCPClient" nocase
    condition:
        ($c1 and ($c2 or $c3)) or $c4
}
