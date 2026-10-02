rule SCRIPT_Dropper_Unknown_ForgeAuto_4003289c
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "4003289ce473284041737c5ae018cd26896df58efb6c979932e4adc97581c42e"
        yarahub_uuid = "4d79dda5-2cea-4f47-a9a3-3c80a803c12f"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3897aa086a98636d5910e9a0cca8317b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "const { spawn } = require('child_process');" ascii
        $s1 = "return new Promise((resolve, _0x8efc5822ec11) => {" ascii
        $s2 = "const _0x8efc5822ecx = url.startsWith('https') ? https : http;" ascii
        $s3 = "const file = fs.createWriteStream(destPath);" ascii
        $s4 = "if (_0x8efc5822ec12.statusCode >= 300 && _0x8efc5822ec12.statusCode < 400 && _0x8efc5822ec12.headers.location) {" ascii
        $s5 = "fs.unlinkSync(destPath);" ascii
        $s6 = "if (_0x8efc5822ec12.statusCode !== 200) {" ascii
        $s7 = "return _0x8efc5822ec11(new Error(`HTTP ${_0x8efc5822ec12.statusCode}`));" ascii
        $s8 = "_0x8efc5822ec12.pipe(file);" ascii
        $s9 = "_0x8efc5822ecy.on('error', _0x8efc5822ec11);" ascii
        $s10 = "const fs = require('fs');" ascii
        $s11 = "const path = require('path');" ascii
        $s12 = "const os = require('os');" ascii
        $s13 = "const http = require('http');" ascii
        $s14 = "const https = require('https');" ascii
        $s15 = "file.close();" ascii
        $s16 = "stdio: 'ignore'," ascii
        $s17 = "windowsHide: true," ascii
        $s18 = "detached: true," ascii
        $s19 = "function _0x8efc5822ec1c(url, destPath, _0x8efc5822ecr = 120000) {" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
