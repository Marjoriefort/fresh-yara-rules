rule SUSP_Bash_CurlPipeBash_Spreader {
    meta:
        description = "Spreader bash minimaliste (curl | bash)"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / spreader"
        confidence  = "medium"
    strings:
        $a = "Spread attempt complete" ascii wide
        $b = "curl -s http://" ascii wide
    condition:
        all of them
}

