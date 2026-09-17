rule WIN_Clipper_Unknown_ClipboardHijack {
    meta:
        description = "DLL clipper (détournement presse-papiers crypto) : API clipboard complètes + DLL compacte"
        author      = "Marjoriefort"
        date        = "2026-09-17"
        reference   = "misses_archive 569 / cluster 282 DLL x 15360 o"
        confidence  = "high"
    strings:
        $a = "OpenClipboard" ascii wide
        $b = "GetClipboardData" ascii wide
        $c = "SetClipboardData" ascii wide
        $d = "EmptyClipboard" ascii wide
        $e = "GetClipboardSequenceNumber" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 100KB and 4 of ($a, $b, $c, $d, $e)
}
