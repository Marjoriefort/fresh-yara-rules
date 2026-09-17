rule MULTI_Dropper_Unknown_VolumeProgram_Bundle {
    meta:
        description = "Archive avec membre 'Volume/program' — bundle dropper multi-plateforme (16 soumissions identiques)"
        author      = "Marjoriefort"
        date        = "2026-09-17"
        reference   = "misses_archive / grappe 16 archives"
        confidence  = "medium-high"
    strings:
        $zip = { 50 4B 03 04 }
        $a   = "Volume/program" ascii wide
    condition:
        $zip and $a
}
