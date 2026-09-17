rule SUSP_ServiceHost_EWRD_Builder_Payload {
    meta:
        description = "EW-RD-SOURCES endpoint builder PDB path (payload level, post-extraction)"
        author      = "Marjoriefort"
        date        = "2026-09-13"
        reference   = "InTheWild.0438 / fresh CS 2026-08-06"
        confidence  = "high"
    strings:
        $pdb = "D:\\Build\\EW-RD-SOURCES\\endpoint\\bin\\x64\\Release\\ServiceHost.exe.pdb"
    condition:
        $pdb
}
