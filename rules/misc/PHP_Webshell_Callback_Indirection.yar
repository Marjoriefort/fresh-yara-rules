rule PHP_Webshell_Callback_Indirection {
    meta:
        description = "PHP webshell using trait/class method indirection ($a($b) arbitrary call)"
        author = "Marjoriefort"
        date = "2026-09-13"
        reference = "InTheWild.0438 / tennc 006_php3"
        confidence = "high"
    strings:
        $a = "public function eat($a, $b)"
        $b = "$a($b);"
        $c = "This is dog drive"
    condition:
        all of them
}
