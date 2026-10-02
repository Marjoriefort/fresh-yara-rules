rule SCRIPT_Dropper_Unknown_ForgeAuto_2ccb863c
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "2ccb863c8ab1168c74718c37a95049226b5d4aeae67340864d3b95d6dd37d851"
        yarahub_uuid = "aa38ef96-6814-449e-bd81-c515b16cc29d"
        famille = "unknown"
        famille_source = "inconnue"
        classe = "script_js"
        etat = "binaire"
        confidence_suggeree = "medium"
        source = "forge_miss M3 v1.9.48"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0182de7fceb3b031218065441157dbda"
        yarahub_reference_link = "https://github.com/Marjoriefort/yara-rules"
    strings:
        $s0 = "jQuery.ajax({" ascii
        $s1 = "var data = {" ascii
        $s2 = "$(document).ready(function() {" ascii
        $s3 = "$('#dp-admin-tabs a:first').addClass('nav-tab-active');" ascii
        $s4 = "$('#dp-admin-tabs a:not(:first)').addClass('nav-tab-inactive');" ascii
        $s5 = "$('.dp-admin-nav-container').hide();" ascii
        $s6 = "$('.dp-admin-nav-container:first').show();" ascii
        $s7 = "$('#dp-admin-tabs a').click(function(){" ascii
        $s8 = "var t = $(this).attr('id');" ascii
        $s9 = "if($(this).hasClass('nav-tab-inactive')){" ascii
        $s10 = "$('#dp-admin-tabs a').addClass('nav-tab-inactive');" ascii
        $s11 = "$(this).removeClass('nav-tab-inactive');" ascii
        $s12 = "$(this).addClass('nav-tab-active');" ascii
        $s13 = "$(\".dpwap-notice-pre .notice-dismiss\").on('click', function(){" ascii
        $s14 = "url: admin_vars.ajax_url," ascii
        $s15 = "data: {action: 'dpwap_dismiss_notice_action'}," ascii
        $s16 = "$(document).on('click', '.dpwap-dismissible .notice-dismiss', function() {" ascii
        $s17 = "// Handle install button click" ascii
        $s18 = "$(document).on('click', '.install-eventprime', function() {" ascii
        $s19 = "action: 'dpwap_dismiss_eventprime_promotion'," ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
