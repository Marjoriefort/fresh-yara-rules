rule SCRIPT_Dropper_Unknown_ForgeAuto_c598a01d
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "c598a01db0708a5ef1608edd792c176c0bb0c7790b8bbe64cb3593aec6bf3df1"
        yarahub_uuid = "d26f632f-e0c7-4276-b3cd-b06fbd82b878"
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
        $s0 = "const vm = require('vm');" ascii
        $s1 = "const os = require('os');" ascii
        $s2 = "const path = require('path');" ascii
        $s3 = "const fs = require('fs');" ascii
        $s4 = "const sandbox = {" ascii
        $s5 = "console," ascii
        $s6 = "async function runEval(code, _0x8efc5822ecr = 30000) {" ascii
        $s7 = "const _0x8efc5822ec1h = `(async () => { ${code} })()`;" ascii
        $s8 = "const output = await script.runInNewContext(sandbox, { timeout: _0x8efc5822ecr });" ascii
        $s9 = "result: output !== undefined ? String(output) : sandbox.result !== undefined ? String(sandbox.result) : null," ascii
        $s10 = "module.exports = { runEval };" ascii
        $s11 = "clearTimeout," ascii
        $s12 = "result: undefined," ascii
        $s13 = "setTimeout," ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
