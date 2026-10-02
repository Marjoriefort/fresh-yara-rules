rule SCRIPT_Dropper_Unknown_ForgeAuto_aaa464f7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "aaa464f724d0b4d6c8efd6e2ab897d5e1daa4152dba1771e25c199c93f550c31"
        yarahub_uuid = "6a4305aa-a71f-4ddd-a60e-9384cda9dc97"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e847743b66dddcfc3afe248a42a71928"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { spawn } = require('child_process');" ascii
        $s1 = "const { getInstallRoot } = require('../installMeta');" ascii
        $s2 = "const { loadInstallMeta } = require('../installMeta');" ascii
        $s3 = "-NonInteractive" ascii
        $s4 = "-ExecutionPolicy" ascii
        $s5 = "const fs = require('fs');" ascii
        $s6 = "const os = require('os');" ascii
        $s7 = "const path = require('path');" ascii
        $s8 = "stdio: 'ignore'," ascii
        $s9 = "windowsHide: true," ascii
        $s10 = "../installMeta" ascii
        $s11 = "install-meta.json" ascii
        $s12 = "-NoProfile" ascii
        $s13 = "detached: true," ascii
        $s14 = "} catch {}" ascii
        $s15 = "function _0x8efc5822ec17(value) {" ascii
        $s16 = "return String(value).replace(/'/g, \"''\");" ascii
        $s17 = "const _0x8efc5822ec18 = loadInstallMeta(installDir);" ascii
        $s18 = "const _0x8efc5822ec19 = path.join(os.tmpdir(), `wra-update-${Date.now()}.zip`);" ascii
        $s19 = "const _0x8efc5822ec1a = encoding === 'base64' ? Buffer.from(content, 'base64') : Buffer.from(content, 'utf8');" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
