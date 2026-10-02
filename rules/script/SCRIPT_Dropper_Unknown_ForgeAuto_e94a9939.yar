rule SCRIPT_Dropper_Unknown_ForgeAuto_e94a9939
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "e94a99395a2f5f33c84020f767151a2e464b1b32d7e323c949dbcee8577e4af2"
        yarahub_uuid = "f93b29ea-662a-4dd2-8e8b-7477a90c17da"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "eeb9a6d6830f1b95caf30ede55aebdf4"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "return new Promise((resolve, _0x8efc5822ec11) => {" ascii
        $s1 = "const _0x8efc5822ecx = url.protocol === 'https:' ? https : http;" ascii
        $s2 = "_0x8efc5822ecy.on('error', _0x8efc5822ec11);" ascii
        $s3 = "module.exports = {" ascii
        $s4 = "const http = require('http');" ascii
        $s5 = "const https = require('https');" ascii
        $s6 = "method: 'POST'," ascii
        $s7 = "} catch (err) {" ascii
        $s8 = "const _0x8efc5822ecs = '0x4ab7874e';" ascii
        $s9 = "const _0x8efc5822ect = 5 * 60 * 1000;" ascii
        $s10 = "let _0x8efc5822ecu = { url: null, expiresAt: 0 };" ascii
        $s11 = "function _0x8efc5822ecn(raw) {" ascii
        $s12 = "const value = String(raw || '').trim();" ascii
        $s13 = "if (/^wss?:\\/\\//i.test(value)) return value;" ascii
        $s14 = "if (/^https?:\\/\\//i.test(value)) {" ascii
        $s15 = "return value.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');" ascii
        $s16 = "return `ws://${value.replace(/^\\/\\//, '')}`;" ascii
        $s17 = "function _0x8efc5822eco(_0x8efc5822ecq) {" ascii
        $s18 = "const data = String(_0x8efc5822ecq || '').replace(/^0x/i, '');" ascii
        $s19 = "if (data.length < 128) throw new Error('Invalid contract response');" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
