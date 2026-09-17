rule SUSP_Bash_NodeJS_Dropper_Installer {
    meta:
        description = "Script bash dropper : installe Node.js portable si absent (prépare un payload JS/jsc)"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / installateurs node"
        confidence  = "medium"
    strings:
        $a = "Node.js not found globally" ascii wide
        $b = "Attempting to download portable version" ascii wide
    condition:
        all of them
}

