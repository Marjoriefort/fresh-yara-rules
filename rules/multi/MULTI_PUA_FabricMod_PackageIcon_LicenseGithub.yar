rule MULTI_PUA_FabricMod_PackageIcon_LicenseGithub {
    meta:
        description = "Mod Minecraft Fabric (structure package + LICENSE_github) soumis en masse — PUA/mods, pattern de soumission"
        author      = "Marjoriefort"
        date        = "2026-09-17"
        reference   = "misses_archive / grappe 9 archives"
        confidence  = "medium"
        note        = "Meme famille que ToggleSprint : mods soumis massivement. Verifier la charge utile en sandbox."
    strings:
        $zip = { 50 4B 03 04 }
        $a   = "assets/package/icon.png" ascii wide
        $b   = "LICENSE_github" ascii wide
    condition:
        $zip and $a and $b
}
