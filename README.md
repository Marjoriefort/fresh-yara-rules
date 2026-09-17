# Règles YARA — Marjoriefort

Collection personnelle de règles YARA forgées sur du malware frais (veille
quotidienne MalwareBazaar / corpus VX-Underground).

**Auteur : Marjoriefort** — veille et détection en environnement personnel.

## Statistiques

- **25 règles** actives, chacune issue d'un vrai échantillon sauvage
- Forgées sur : downloader botnet (Linux), clipper crypto (Windows DLL),
  kits phishing (web), mods Minecraft soumis en masse (PUA), stealer macOS…
- Chaque règle est testée contre un corpus de faux positifs avant intégration

## Structure

Les règles sont rangées par préfixe de plateforme (nomenclature
`<Plateforme>_<Catégorie>_<Famille>_<Détail>`) :

```
rules/
├── win/     binaires Windows (PE)        → WIN_*
├── lin/     scripts/binaires Linux       → LIN_*
├── mac/     macOS                        → MAC_*
├── multi/   multi-plateforme (jar/zip)   → MULTI_*
├── script/  scripts JS/VBS/PS/bash       → SCRIPT_*
└── web/     HTML/HTA/phishing            → WEB_*
```

## Utilisation

```bash
# Une règle seule
yara rules/win/WIN_Clipper_Unknown_ClipboardHijack.yar /chemin/a/scanner

# Toute la collection (récursif)
yara -r rules/ /chemin/a/scanner
```

## Nomenclature

| Champ | Valeurs |
|---|---|
| Plateforme | `WIN` `LIN` `MAC` `ANDROID` `MULTI` `SCRIPT` `WEB` |
| Catégorie | `Trojan` `Downloader` `Dropper` `Clipper` `Stealer` `Ransomware` `Miner` `Phish` `Webshell` `Spreader` `PUA` |
| Famille | nom de famille connu, ou `Unknown` |
| Détail | ce qui distingue la règle |

## Métadonnées

Chaque règle porte : `author`, `date`, `description`, `reference` (échantillon
d'origine), `confidence`. Certaines portent un champ `note` quand le verdict
demande une vérification complémentaire (PUA, greyware).

## Licence

BSD-3-Clause — voir [LICENSE](LICENSE). Utilisation libre, avec attribution.
Les règles sont fournies « en l'état », sans garantie de détection exhaustive.

## Faux positifs

Si une règle flagge un fichier légitime : ouvrez une issue avec le hash SHA256
du fichier et la règle concernée. Les règles `confidence = "medium"` ou avec
`note` méritent une vérification avant tout blocage automatique.

## Remerciements / sources

- [MalwareBazaar](https://bazaar.abuse.ch/) & [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) — la matière première quotidienne
- [VX-Underground](https://vx-underground.org/) — les corpus InTheWild
- Les collections communautaires qui entourent cette collection
