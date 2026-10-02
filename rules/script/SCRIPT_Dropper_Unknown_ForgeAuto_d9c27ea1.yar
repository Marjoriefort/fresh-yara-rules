rule SCRIPT_Dropper_Unknown_ForgeAuto_d9c27ea1
{
    meta:
        author = "Marjoriefort"
        description = "Detects Unknown (script_js, etat binaire)"
        date = "2026-10-02"
        reference_sha256 = "d9c27ea15b0a380b970b8eca0d2abb34973888be9f5b65178ea8d558a3c09d0d"
        yarahub_uuid = "86c1292d-7718-4cc7-8750-09488acc4e85"
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
        $s0 = "const VERSION = '3.1.6', $ = id => document.getElementById(id);" ascii
        $s1 = "const icon = name => `<svg aria-hidden=\"true\"><use href=\"#i-${name}\"/></svg>`;" ascii
        $s2 = "read(key,fallback) { try { return JSON.parse(localStorage.getItem('mobix.' + key)) ?? fallback; } catch { return fallback; } }," ascii
        $s3 = "write(key,value) { try { localStorage.setItem('mobix.' + key,JSON.stringify(value)); } catch { /* Restricted storage remains optional. */ } }" ascii
        $s4 = "const brands = window.MOBIX_CATALOG, dictionaries = window.MOBIX_I18N;" ascii
        $s5 = "const models = brands.flatMap(b => b.models.map(name => ({name,brand:b.name,os:b.os,color:b.color,id:b.name + ':' + name})));" ascii
        $s6 = "const savedPrefs = storage.read('preferences',{});" ascii
        $s7 = "const prefs = {language:'en',theme:'dark',speed:'normal',autoscroll:true,sound:false,scenario:'success',...(savedPrefs && typeof savedPrefs === 'object' ? savedPrefs : {})};" ascii
        $s8 = "const locale = () => ({en:'en-US',zh:'zh-CN',ru:'ru-RU'}[prefs.language]);" ascii
        $s9 = "const dateTime = iso => new Date(iso).toLocaleString(locale(),{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false,timeZone:'Europe/Moscow'});" ascii
        $s10 = "const time = iso => new Date(iso).toLocaleTimeString(locale(),{hour12:false,timeZone:'Europe/Moscow'});" ascii
        $s11 = "const brandImage = brand => `<img class=\"${colorLogos.has(brand) ? '' : 'mono-logo'}\" src=\"assets/brands/${brand.toLowerCase()}.svg\" alt=\"${esc(brand)}\">`;" ascii
        $s12 = "const fullName = m => m.name.toLowerCase().startsWith(m.brand.toLowerCase()) || m.brand === 'Apple' ? m.name : m.brand + ' ' + m.name;" ascii
        $s13 = "const duration = () => ({fast:7000,normal:15000,slow:25000}[prefs.speed]);" ascii
        $s14 = "const newId = () => 'MX-' + [...crypto.getRandomValues(new Uint8Array(3))].map(n => n.toString(16).padStart(2,'0')).join('').toUpperCase();" ascii
        $s15 = "let selected = models.find(m => m.brand === 'Samsung' && m.name === 'Galaxy S24 Ultra'), operation = opList[0];" ascii
        $s16 = "let connectionTimers = [], toastTimer, toastState, logs = [], page = 'workspace', filterBrand = 'all', favoriteOnly = false, visibleLimit = 40, audioContext;" ascii
        $s17 = "const savedFavorites = storage.read('favorites',[]);" ascii
        $s18 = "let favorites = new Set(Array.isArray(savedFavorites) ? savedFavorites.filter(id => models.some(m => m.id === id)) : []);" ascii
        $s19 = "const savedHistory = storage.read('history',[]);" ascii
    condition:
        true and filesize < 50MB and 2 of them and 1 of ($s0, $s1, $s2, $s3, $s4)
}
