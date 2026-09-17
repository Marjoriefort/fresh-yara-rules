rule SUSP_JS_HexObfuscated_ActiveX_Launcher {
    meta:
        description = "JS obfusqué (identifiants _0x) instanciant ActiveX sous WScript — dropper JScript frais"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / cluster JS _0x"
        confidence  = "medium-high"
    strings:
        $a = "WScript" ascii wide
        $b = "ActiveXObject(_0x" ascii wide
    condition:
        all of them
}

