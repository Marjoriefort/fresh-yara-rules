rule SUSP_Bitdefender_Impersonation_Zip_Bundle {
    meta:
        description = "ZIP bundle impersonating Bitdefender (bitdefender.exe + ServiceInstance.dll members)"
        author      = "Marjoriefort"
        date        = "2026-09-13"
        reference   = "InTheWild.0438 / fresh CS 2026-08-06"
        confidence  = "medium-high"
    strings:
        $zip = { 50 4B 03 04 }
        $bde = "bitdefender.exe"
        $svc = "ServiceInstance.dll"
    condition:
        $zip and $bde and $svc
}

