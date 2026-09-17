rule Phish_VN_TechSupport_WebsiteDown_Kit {
    meta:
        description = "Kit phishing tech-support vietnamien : fausse page 'site hors service' a arc-en-ciel (BazaCall-like)"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / cluster HTML scam"
        confidence  = "high"
    strings:
        $a = "Website hi" ascii wide nocase
        $b = "conic-gradient" ascii wide
        $c = ".rainbow" ascii wide
    condition:
        $a and 1 of ($b, $c)
}
