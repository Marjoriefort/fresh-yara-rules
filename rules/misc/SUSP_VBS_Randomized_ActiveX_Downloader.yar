rule SUSP_VBS_Randomized_ActiveX_Downloader {
    meta:
        description = "Dropper VBS obfusque : ActiveXObject a identifiant randomise (20 MAJ), SaveToFile, .Run"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / grappe VBS randomisee"
        confidence  = "medium-high"
    strings:
        $a = /ActiveXObject\([A-Z]{15,25}\)/ ascii wide
        $b = "SaveToFile" ascii wide nocase
        $c = ".Run" ascii wide
    condition:
        $a and 1 of ($b, $c)
}
