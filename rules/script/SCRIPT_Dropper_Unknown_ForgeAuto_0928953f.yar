rule SCRIPT_Dropper_Unknown_ForgeAuto_0928953f
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "0928953feda445aa8190599bc9500c3151c139ba9f4d2ee8cdba6a23ab5d0269"
        yarahub_uuid = "59a74f6e-5fae-428f-b898-579fd6f51ba4"
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
        $s2 = "if (_0x8efc5822ec12.statusCode !== 200) {" ascii
        $s3 = "_0x8efc5822ecy.on('error', _0x8efc5822ec11);" ascii
        $s4 = "const vm = require('vm');" ascii
        $s5 = "const http = require('http');" ascii
        $s6 = "const https = require('https');" ascii
        $s7 = "const sandbox = {" ascii
        $s8 = "console," ascii
        $s9 = "function _0x8efc5822ec3v(panelUrl) {" ascii
        $s10 = "return panelUrl.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:');" ascii
        $s11 = "function _0x8efc5822ec3w(panelUrl, token) {" ascii
        $s12 = "const base = _0x8efc5822ec3v(panelUrl);" ascii
        $s13 = "const _0x8efc5822ecy = _0x8efc5822ecx.get(url, { headers: { 'X-Agent-Token': token }, timeout: 15000 }, (_0x8efc5822ec12) => {" ascii
        $s14 = "_0x8efc5822ec12.on('data', (c) => { body += c; });" ascii
        $s15 = "return _0x8efc5822ec11(new Error(`Script fetch HTTP ${_0x8efc5822ec12.statusCode}`));" ascii
        $s16 = "function _0x8efc5822ec3x(code) {" ascii
        $s17 = "exports: module.exports," ascii
        $s18 = "const _0x8efc5822ec1h = `(function(module, exports, console, Buffer) {\\n${code}\\n})(module, module.exports, console, Buffer);`;" ascii
        $s19 = "vm.runInNewContext(_0x8efc5822ec1h, sandbox, { timeout: 5000, filename: 'remote-agent-script.js' });" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
