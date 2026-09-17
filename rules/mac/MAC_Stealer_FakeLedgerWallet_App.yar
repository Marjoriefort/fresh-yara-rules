rule MAC_Stealer_FakeLedgerWallet_App {
    meta:
        description = "Faux Ledger Wallet.app (macOS) — bundle imitant le logiciel Ledger, voleur de crypto a confirmer"
        author      = "Marjoriefort"
        date        = "2026-09-17"
        reference   = "misses_archive / f8d09bb7"
        confidence  = "medium"
        note        = "Structure .app imitant Ledger Wallet ; verifier la signature Apple et le binaire MacOS en sandbox"
    strings:
        $a = "Ledger Wallet.app/Contents/MacOS/Ledger Wallet" ascii wide
        $b = "Ledger Wallet.app/Contents/_CodeSignature/" ascii wide
        $c = "ledger-live.css" ascii wide
    condition:
        uint32(0) == 0x04034b50 and $a and 1 of ($b, $c)
}
