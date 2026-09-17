rule SUSP_HTML_XMLHTTP_Redirect_Kit {
    meta:
        description = "HTML avec exfiltration XMLHTTP + redirection window.location — kit phishing frais"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / cluster HTML"
        confidence  = "medium"
    strings:
        $a = "<script" ascii wide
        $b = "XMLHTTP" ascii wide nocase
        $c = "window.location" ascii wide nocase
    condition:
        all of them
}

