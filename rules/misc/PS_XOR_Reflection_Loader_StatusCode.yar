rule PS_XOR_Reflection_Loader_StatusCode {
    meta:
        description = "Obfuscated PowerShell .NET loader (builder statusCode family): XOR byte decode + reflection + HMAC-32 + scriptblock/IEX exec"
        author      = "Marjoriefort"
        date        = "2026-09-13"
        reference   = "InTheWild.0438 / fresh powershell 2026-08-15 + tag_powershell"
        confidence  = "high"
    strings:
        $err = /Error: statusCode [0-9]{5,6}/
        $xor = "$b[$i]=$b[$i] -bxor"
        $ref = "GetMethods()|Where-Object{$_.Name -eq $n"
        $iex = "'-Exp' + 'ress' + 'io' + 'n'"
    condition:
        $err and 1 of ($xor, $ref, $iex)
}
