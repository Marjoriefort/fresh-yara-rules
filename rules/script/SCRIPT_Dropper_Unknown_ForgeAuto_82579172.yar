rule SCRIPT_Dropper_Unknown_ForgeAuto_82579172
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "8257917242bbf351a1ce138e9d4d668e3403e8c0325081f0aa5e3be636c9951e"
        yarahub_uuid = "9a0b8456-2605-4637-8710-b957d7e5b3db"
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
        $s0 = "const { execFile } = require('child_process');" ascii
        $s1 = "const _0x8efc5822ec1b = promisify(execFile);" ascii
        $s2 = "const { stdout, stderr } = await _0x8efc5822ec1b(" ascii
        $s3 = "{ timeout: _0x8efc5822ecr, maxBuffer: 10 * 1024 * 1024, windowsHide: true }" ascii
        $s4 = "stdout: err.stdout || ''," ascii
        $s5 = "exitCode: err.code," ascii
        $s6 = "const { promisify } = require('util');" ascii
        $s7 = "stderr: err.stderr || err.message," ascii
        $s8 = "} catch (err) {" ascii
        $s9 = "success: false," ascii
        $s10 = ", stderr: stderr ||" ascii
        $s11 = "async function runCmd(command, _0x8efc5822ecr = 120000) {" ascii
        $s12 = "module.exports = { runCmd };" ascii
        $s13 = "'cmd.exe'," ascii
        $s14 = "['/c', command]," ascii
        $s15 = "cmd.exe" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
