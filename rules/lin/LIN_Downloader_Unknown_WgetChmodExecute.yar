rule LIN_Downloader_Unknown_WgetChmodExecute {
    meta:
        description = "Script shell downloader : wget+curl, chmod 777, execution, effacement (rm -rf) — botnet style"
        author      = "Marjoriefort"
        date        = "2026-09-17"
        reference   = "misses_archive / grappe 5.182.210.174"
        confidence  = "high"
    strings:
        $a = "wget http://" ascii wide
        $b = "curl -O http://" ascii wide
        $c = "chmod 777" ascii wide
        $d = "rm -rf" ascii wide
    condition:
        $c and $d and 1 of ($a, $b)
}
