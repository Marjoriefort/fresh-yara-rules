rule ZIP_Python_FlowSsh_Bundle_ACR {
    meta:
        description = "ZIP bundle: embedded Python profiler/sampling suite + FlowSshNet SSH automation (ACRStealer-tagged)"
        author      = "Marjoriefort"
        date        = "2026-09-13"
        reference   = "InTheWild.0438 / ACRStealer 33c8aee0"
        confidence  = "medium"
    strings:
        $zip = { 50 4B 03 04 }
        $fs1 = "FlowSshNet_Exec.ps1"
        $fs2 = "FlowSshNet_Sftp.ps1"
        $spy = "sampling/binary_collector.pyc"
    condition:
        $zip and $fs1 and $fs2 and $spy
}
