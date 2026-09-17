rule ASP_VBScript_Encoded_Webshell {
    meta:
        description = "Encoded VBScript ASP page (Microsoft Script Encoder) — webshell-grade legacy"
        author = "Marjoriefort"
        date = "2026-09-13"
        reference = "InTheWild.0438 / tennc 016_shell.asp + 034_CyberSpy5"
        confidence = "medium"
    strings:
        $h   = "<%@ LANGUAGE = VBScript.Encode %>"
        $enc = "@#@~^"
    condition:
        $h and $enc
}

