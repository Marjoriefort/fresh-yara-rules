rule MULTI_Sample_AgentTesla_ed343f78_Extrait
{
    meta:
        author = "Marjoriefort"
        description = "Detects AgentTesla (inconnu, etat extrait)"
        date = "2026-09-21"
        reference_sha256 = "ed343f78fac90a8c05df28d2b2ac47fc3a8b62c968597f6de15112565916e97f"
        yarahub_uuid = "ba8b0676-0718-4e1d-a4b4-100684bd0011"
        famille = "AgentTesla"
        famille_source = "reputation"
        classe = "inconnu"
        etat = "extrait"
        confidence_suggeree = "low"
        source = "forge_miss M3 v1.9.17"
malpedia_family = "agenttesla"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "83d1ee085e069357c270cf8fb159ae61"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "IEGHXFITUDTALQEX51056['push'](IEGHXFITUDTALQEX51056['shift']());" ascii
        $s1 = "IEGHXFITUDTALQEX33102, 0x7fd8b), (function (IEGHXFITUDTALQEX24054, IEGHXFITUDTALQEX9845) {" ascii
        $s2 = "if ('XyIlO' !== IEGHXFITUDTALQEX82424(0x5c2))" ascii
        $s3 = "IEGHXFITUDTALQEX58695[IEGHXFITUDTALQEX82424(0x46b)](IEGHXFITUDTALQEX58695['shift']());" ascii
        $s4 = "IEGHXFITUDTALQEX58695[IEGHXFITUDTALQEX82424(0x46b)](IEGHXFITUDTALQEX58695[IEGHXFITUDTALQEX82424(0x65e)]());" ascii
        $s5 = "IEGHXFITUDTALQEX41981, 0x7c7a0), function (IEGHXFITUDTALQEX78400, IEGHXFITUDTALQEX70636) {" ascii
        $s6 = "IEGHXFITUDTALQEX72810(0x8a, 0x1ec)," ascii
        $s7 = "IEGHXFITUDTALQEX72810(-0xbd, -0x1d4)," ascii
        $s8 = "IEGHXFITUDTALQEX86317(0x1e2)" ascii
        $s9 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(-0x165, -0x1e7)" ascii
        $s10 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX86317(0x233)" ascii
        $s11 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x13e, 0x2d5)" ascii
        $s12 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(-0xcb, -0x16c)" ascii
        $s13 = "'IEGHXFITUDTALQEXOOO': 'AMX_IEGHXFITUDTALQEXPPPPE'" ascii
        $s14 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x186, -0x9f)" ascii
        $s15 = "'IEGHXFITUDTALQEXOOO': 'AMX_INT8'" ascii
        $s16 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x1d1, 0x366)" ascii
        $s17 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x392, 0x577)" ascii
        $s18 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x2a6, 0x112)" ascii
        $s19 = "'IEGHXFITUDTALQEXOOO': IEGHXFITUDTALQEX72810(0x219, -0xb)" ascii
    condition:
        true and filesize < 50MB and 3 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
