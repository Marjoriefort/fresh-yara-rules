rule MULTI_Famille_837ffd60
{
    meta:
        author = "Marjoriefort"
        description = "Famille MULTI_Famille_837ffd60 - noyau stable de 3 membre(s) ; identifiants randomises exclus (synthese v1.9.2)"
        date = "2026-10-02"
        reference_sha256 = "837ffd60d165a52d0555ed15e1e9dafcb421f82c7519026e9a555f1572c544c7"
        yarahub_uuid = "ac7485d2-8a38-490b-b1b5-465a260e1f56"
        famille = "MULTI_Famille_837ffd60"
        classe = "inconnu"
        confidence_suggeree = "medium"
        source = "forge_miss M3 famille v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fd03576c3db9a39ca7b185b54a939536"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "</dsig:Transforms>" ascii
        $s1 = "<dsig:Transforms>" ascii
        $s2 = "asmv1:assembly>" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2)
}
