rule SUSP_Script_PowerShell_Hidden_Launcher {
    meta:
        description = "Script (JS/VBS) lançant PowerShell en mode furtif — dropper frais MalwareBazaar"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / cluster misses web"
        confidence  = "medium"
    strings:
        $a = "WindowStyle" ascii wide
        $b = "-ExecutionPolicy Bypass" ascii wide
        $c = "NoProfile" ascii wide
        $d = "WScript.Shell" ascii wide
        $e = "ActiveXObject" ascii wide
        $f = "powershell" ascii wide nocase
    condition:
        $f and 1 of ($a, $b, $c) and 1 of ($d, $e)
}
