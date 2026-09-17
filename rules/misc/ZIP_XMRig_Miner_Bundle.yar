rule ZIP_XMRig_Miner_Bundle {
    meta:
        description = "Bundle XMRig (mineur non consenti) — archive avec WinRing0 driver"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / bundle xmrig"
        confidence  = "medium"
    strings:
        $zip = { 50 4B 03 04 }
        $x1  = "xmrig-v2/WinRing0x64.sys"
        $x2  = "xmrig-v2/start.cmd"
    condition:
        $zip and 1 of ($x1, $x2)
}
