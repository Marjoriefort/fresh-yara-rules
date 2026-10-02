rule SCRIPT_Dropper_Unknown_ForgeAuto_0507f067_Script
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat script)"
        date = "2026-10-01"
        reference_sha256 = "0507f067f172fb4d8d152d360b362ae0de6d6fd77c4c8f4c6c1560c875b5a4ff"
        yarahub_uuid = "9fde6f70-7d28-4a90-972c-59d3eb4e66f1"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "script"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6b8f860c3941dc76a3087832cffe9b5b"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "index.php" ascii
        $s1 = "method: 'POST'," ascii
        $s2 = "function () {" ascii
        $s3 = "} catch (err) {" ascii
        $s4 = "SecurityError" ascii
        $s5 = "const root = document.getElementById('fv-app');" ascii
        $s6 = "upload: root.dataset.uploadUrl," ascii
        $s7 = "const backUrl = root.dataset.backUrl || 'index.php';" ascii
        $s8 = "const nextUrl = root.dataset.nextUrl || 'index.php';" ascii
        $s9 = "const NO_FACE_HINT = 'No detectamos un rostro claro en el" ascii
        $s10 = "screens: Array.prototype.slice.call(root.querySelectorAll('[data-fv-screen]'))," ascii
        $s11 = "coach: root.querySelector('.fv-coach')," ascii
        $s12 = "hint: root.querySelector('[data-fv-hint]')," ascii
        $s13 = "dots: root.querySelectorAll('.fv-dot')," ascii
        $s14 = "lines: root.querySelectorAll('.fv-dot-line')," ascii
        $s15 = "steps: root.querySelectorAll('[data-fv-steps] li')," ascii
        $s16 = "resultIcon: root.querySelector('[data-fv-result-icon]')," ascii
        $s17 = "resultTitle: root.querySelector('[data-fv-result-title]')," ascii
        $s18 = "resultBody: root.querySelector('[data-fv-result-body]')," ascii
        $s19 = "retry: root.querySelector('[data-fv-action=\"retry\"]')," ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
