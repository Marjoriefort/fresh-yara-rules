rule SCRIPT_Dropper_Unknown_ForgeAuto_31bfc5b7
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "31bfc5b7083690b9237c49f7d0c1802977fcf6af5cfc5738565b87fcfb129bbb"
        yarahub_uuid = "336e580b-9d11-4ec1-ae4e-be9d36ca1758"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "cba9845f93eb0c9d4e8e447fe95ef777"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "jQuery(document).ready(function($) {" ascii
        $s1 = "event.preventDefault();" ascii
        $s2 = "Please enter a valid email address." ascii
        $s3 = "Please provide details about your customization request." ascii
        $s4 = "method: 'POST'," ascii
        $s5 = "user_email" ascii
        $s6 = "plugin_select" ascii
        $s7 = "customizationType" ascii
        $s8 = "const modal = $('#dtwap-customizeModal');" ascii
        $s9 = "const closeButtons = $('.dtwap-close-button');" ascii
        $s10 = "const customizeLinks = $('.dpwap_customize_link');" ascii
        $s11 = "const form = $('#dtwap-customizeForm');" ascii
        $s12 = "// const modalLogo = $('.modal-logo');" ascii
        $s13 = "const modalHeadings = $('#dtwap-customizeModal h2, #dtwap-customizeModal #p3');" ascii
        $s14 = "// Validation Error Messages" ascii
        $s15 = "const emailError = \"Please enter a valid email address.\";" ascii
        $s16 = "const customizationError = \"Please provide details about your customization request.\";" ascii
        $s17 = "customizeLinks.each(function() {" ascii
        $s18 = "$(this).on('click', function(event) {" ascii
        $s19 = "pluginSelect.val($(this).data('plugin'));" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
