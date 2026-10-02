rule SCRIPT_Dropper_Unknown_ForgeAuto_990bfd2e
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-01"
        reference_sha256 = "990bfd2e0d24ebc4bcfa5f250efa72ab5014f6f401e51e9f2251a86aaff64124"
        yarahub_uuid = "83449088-10e8-468e-9b08-2b8c97388494"
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
        $s0 = "const fs = require('fs');" ascii
        $s1 = "const path = require('path');" ascii
        $s2 = "install-meta.json" ascii
        $s3 = "CaptureScreen.exe" ascii
        $s4 = "node.exe" ascii
        $s5 = "const META_FILE = 'install-meta.json';" ascii
        $s6 = "const DEFAULT_META = {" ascii
        $s7 = "launcherExe: 'WinAgent.exe'," ascii
        $s8 = "launcherVbs: 'start-agent.vbs'," ascii
        $s9 = "captureExe: 'CaptureScreen.exe'," ascii
        $s10 = "startupScript: 'setup-startup.ps1'," ascii
        $s11 = "launcherCmd: 'WinAgent.cmd'," ascii
        $s12 = "runCmd: 'run-agent.cmd'," ascii
        $s13 = "if (process.pkg) {" ascii
        $s14 = "const _0x8efc5822ec8 = path.dirname(process.execPath);" ascii
        $s15 = "if (fs.existsSync(path.join(_0x8efc5822ec8, 'app', 'src', 'index.js'))) {" ascii
        $s16 = "if (fs.existsSync(path.join(_0x8efc5822ec8, '..', 'app', 'src', 'index.js'))) {" ascii
        $s17 = "if (fs.existsSync(path.join(_0x8efc5822ec8, 'config.json'))) {" ascii
        $s18 = "const _0x8efc5822ec3t = path.resolve(__dirname, '..', '..');" ascii
        $s19 = "fs.existsSync(path.join(_0x8efc5822ec3t, 'node.exe'))" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
