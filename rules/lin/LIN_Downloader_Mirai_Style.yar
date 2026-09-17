rule LIN_Downloader_Mirai_Style {
    meta:
        description = "Script shell downloader style Mirai : curl C2/bins/... | bash, par architecture"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Formation veille 2026-09-16 / cluster cirqueira"
        confidence  = "high"
    strings:
        $a = "curl -s http://" ascii wide
        $b = "/bins/" ascii wide
        $c = "| bash" ascii wide
        $d = "Payload specifique pour architecture:" ascii wide
    condition:
        3 of ($a,$b,$c,$d)
}
