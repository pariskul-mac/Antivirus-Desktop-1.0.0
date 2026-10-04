/*
   CyberGuard AI - InfoStealer & Credential Harvester Detection Rules
   Targets data theft: Browser passwords, Cookies, Discord tokens, CryptUnprotectData.
*/

rule Detect_Browser_Credential_Stealer {
    meta:
        description = "ตรวจจับโค้ดพยายามดักขโมยฐานข้อมูลรหัสผ่านและคุกกี้ของเว็บเบราว์เซอร์ (Chrome, Edge, Brave)"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $p1 = "Login Data" nocase
        $p2 = "Web Data" nocase
        $p3 = "CryptUnprotectData" ascii wide
        $p4 = "AppData\\Local\\Google\\Chrome\\User Data" nocase
        $p5 = "AppData\\Local\\Microsoft\\Edge\\User Data" nocase
    condition:
        ($p1 or $p2) and $p3 and ($p4 or $p5)
}

rule Detect_Token_Grabber_Discord {
    meta:
        description = "ตรวจจับสคริปต์ขโมย Discord Token หรือแอบส่งข้อมูลออกทาง Webhook"
        author = "CyberGuard AI"
        severity = "DANGER"
    strings:
        $d1 = "api/webhooks" nocase
        $d2 = "discord.com/api/webhooks" nocase
        $d3 = "discordapp.com/api/webhooks" nocase
        $t1 = "leveldb" nocase
        $t2 = "Local Storage\\leveldb" nocase
        $t3 = "token" nocase
    condition:
        any of ($d*) and any of ($t*)
}
