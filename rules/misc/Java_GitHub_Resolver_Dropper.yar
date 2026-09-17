rule Java_GitHub_Resolver_Dropper {
    meta:
        description = "Dropper Java deguise en projet GitHub (classes obfusquees, resolver)"
        author      = "Marjoriefort"
        date        = "2026-09-16"
        reference   = "Veille fraicheur 2026-09-14 / jar 792550b4"
        confidence  = "medium"
    strings:
        $a = "murzrynResolver" ascii wide
        $b = "LICENSE_github" ascii wide
    condition:
        all of them
}
