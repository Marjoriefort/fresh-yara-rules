rule JS_Bytenode_JSC_Loader {
    meta:
        description = "bytenode loader executing compiled V8 bytecode (app.protected.jsc) — payload invisible to string scanning"
        author = "Marjoriefort"
        date = "2026-09-13"
        reference = "InTheWild.0438 / tag_js 0fc4a52a"
        confidence = "medium"
    strings:
        $b = "require('bytenode')"
        $j = "app.protected.jsc"
    condition:
        $b and $j
}

