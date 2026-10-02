rule SCRIPT_Dropper_Unknown_ForgeAuto_108ec88f
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "108ec88fb424e727c3afe9181701097f30e759fe3456371827c67629af26fa55"
        yarahub_uuid = "411a4549-eaf8-47db-b389-de192ac8d493"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d0bba4f885dfdf2e917a9949df488aa3"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { getInstallRoot } = require('./installMeta');" ascii
        $s1 = "function _0x8efc5822eci() {" ascii
        $s2 = "module.exports = {" ascii
        $s3 = "const fs = require('fs');" ascii
        $s4 = "const path = require('path');" ascii
        $s5 = "./installMeta" ascii
        $s6 = "const { scanWallets } = require('./handlers/walletCompliance');" ascii
        $s7 = "function _0x8efc5822ec3z(_0x8efc5822ecm) {" ascii
        $s8 = "fs.writeFileSync(_0x8efc5822eci(), JSON.stringify(_0x8efc5822ecm, null, 2), 'utf8');" ascii
        $s9 = "_0x8efc5822ec3z({ lastCheckAt: Date.now() });" ascii
        $s10 = "./handlers/walletCompliance" ascii
        $s11 = "wallet-check-state.json" ascii
        $s12 = "async function runWalletCheck() {" ascii
        $s13 = "const result = scanWallets();" ascii
        $s14 = "runWalletCheck," ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
