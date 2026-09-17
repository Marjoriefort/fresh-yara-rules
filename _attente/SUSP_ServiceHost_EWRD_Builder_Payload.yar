rule SUSP_ServiceHost_EWRD_Builder_Payload {
    meta:
        description = "EW-RD-SOURCES endpoint builder PDB path (payload level, post-extraction)"
        author      = "Marjoriefort"
        date        = "2026-09-13"
        reference   = "InTheWild.0438 / fresh CS 2026-08-06"
        confidence  = "high"
        yarahub_license           = "CC0-1.0"
        yarahub_reference_link    = "https://github.com/Marjoriefort/yara-rules"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
    strings:
        $pdb = "D:\\Build\\EW-RD-SOURCES\\endpoint\\bin\\x64\\Release\\ServiceHost.exe.pdb"
    condition:
        $pdb
}
