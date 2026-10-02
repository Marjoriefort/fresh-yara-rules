rule SCRIPT_Dropper_Unknown_ForgeAuto_6c79c3b4
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "6c79c3b4f02d5db311f2b4b5bde9d26515a49d7882734e549668db47de45320e"
        yarahub_uuid = "2171c538-8645-4404-86fc-da2652c35e6c"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "77d3ea9e31ce5b30ff156a53ae2c1ab9"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = ")).join(" ascii
        $s1 = "'use strict';" ascii
        $s2 = "(window);" ascii
        $s3 = "schemaVersion" ascii
        $s4 = "createdAt" ascii
        $s5 = "operationId" ascii
        $s6 = "sessionId" ascii
        $s7 = "HarmonyOS" ascii
        $s8 = "Reports describe generated local profile values; they do not read a handset. */" ascii
        $s9 = "const range = max-min+1, limit = Math.floor(4294967296/range)*range;" ascii
        $s10 = "let value; do { value = root.crypto.getRandomValues(new Uint32Array(1))[0]; } while (value >= limit);" ascii
        $s11 = "const pick = values => values[integer(0,values.length-1)];" ascii
        $s12 = "const storageGB = pick([128,256,512]), usedGB = integer(18,Math.floor(storageGB*.78));" ascii
        $s13 = "const appleLegacy = /iPhone (7|8|X)(\\s|$)/.test(profile.name);" ascii
        $s14 = "const versions = platform === 'iOS' ? appleLegacy ? ['15.7','15.8'] : ['17.6','18.0','18.1'] : platform === 'HarmonyOS' ? ['4.0','4.2'] : ['12','13','14'];" ascii
        $s15 = "const id = 'MXR-' + Array.from(root.crypto.getRandomValues(new Uint8Array(8)),n => n.toString(16).padStart(2,'0')).join('').toUpperCase();" ascii
        $s16 = "if (!value || value.schemaVersion !== 1 || value.source !== 'local-profile' || value.physicalDeviceModified !== false || !/^MXR-[A-F0-9]{16}$/.test(value.id)) return null;" ascii
        $s17 = "const operationId = value.operationId ?? 'info', sessionId = value.sessionId ?? '', elapsedSeconds = value.elapsedSeconds ?? 0, outcome = value.outcome ?? 'success';" ascii
        $s18 = "const normalized = {...value,operationId,sessionId,elapsedSeconds,outcome};" ascii
        $s19 = "return Object.freeze(Object.fromEntries(fields.map(key => [key,normalized[key]])));" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
