# Phase 5 : outils, commandes et lecture des résultats

Versions de référence vérifiées le 23.11.2026 : `partage/referentiels.md`, section 4. Toujours noter la version réellement utilisée dans `security/05-statique/versions.txt`.

## Sommaire
1. Ordre conseillé et sorties
2. Secrets (historique git complet)
3. Dépendances et chaîne d'approvisionnement
4. SAST par règles
5. Base Supabase
6. CI et conteneurs
7. Qualifier un signal

## 1. Ordre conseillé et sorties

| # | Contrôle | Outil | Sortie dans `security/05-statique/` |
|---|---|---|---|
| 1 | Migrations, policies, fonctions | `scripts/revue_sql.py` + lecture humaine | `revue-sql.md` |
| 2 | Lints de sécurité Supabase | `supabase db advisors --type security` (labo) | `advisors.txt` |
| 3 | Config, secrets visibles, bundle | `scripts/scan_config.py` (après `npm run build`) | `config.md` |
| 4 | Secrets dans tout l'historique | TruffleHog | `trufflehog.json` |
| 5 | Dépendances | `scripts/deps_check.py --registre`, osv-scanner, Socket CLI | `dependances.md`, `osv.json` |
| 6 | SAST | Semgrep CE ou Opengrep + `assets/semgrep-vibecoding.yml` | `semgrep.sarif` |
| 7 | CI | zizmor (si `.github/workflows/`) | `zizmor.txt` |
| 8 | Synthèse | à la main, format ci-dessous | `synthese.md` |

Les étapes 1 et 3 suffisent pour une **mission express**, avec TruffleHog si le dépôt a un historique.

Tous ces contrôles sont **passifs** : ils lisent le dépôt. Seule l'étape 2 demande le labo démarré. Aucun ne touche un environnement hébergé.

## 2. Secrets (historique git complet)

```bash
trufflehog git file://. --results=verified,unknown --json > security/05-statique/trufflehog.json
```

- Scanner **tout** l'historique, pas seulement le dernier commit : un secret supprimé reste dans git.
- TruffleHog peut **vérifier** un secret en l'essayant auprès du fournisseur. C'est une requête vers un service tiers avec un secret de PA : la faire seulement avec son accord. Sinon : `--no-verification`.
- Alternative : Betterleaks (reprend la config gitleaks). gitleaks est en maintenance.
- Un secret trouvé est **confirmé** comme exposé (le fichier ou le commit le montre). La mesure immédiate est la rotation, même si le secret a été supprimé depuis.
- Ne jamais recopier un secret en clair dans un livrable : 4 premiers caractères, puis « [caviardé] ».

## 3. Dépendances et chaîne d'approvisionnement

```bash
python3 scripts/deps_check.py . --registre --sortie security/05-statique/dependances.md
osv-scanner scan source -r . --format json > security/05-statique/osv.json
npm audit --json > security/05-statique/npm-audit.json        # complément, CVE connues seulement
# Socket CLI (paquets malveillants) : voir « socket --help » pour la commande de scan de la version installée
```

- Pour chaque CVE trouvée, chercher l'exploitabilité réelle : `https://api.first.org/data/v1/epss?cve=<CVE>` (score EPSS et percentile) et la présence dans le catalogue CISA KEV (`https://github.com/cisagov/kev-data`). Une CVE dans KEV ou avec un EPSS élevé monte en priorité.
- Une CVE dans une dépendance de développement non livrée au navigateur pèse moins : le dire.
- npm 12 bloque par défaut les scripts d'installation des dépendances : vérifier la version de npm utilisée par PA et la liste approuvée (`npm approve-scripts`).

## 4. SAST par règles

```bash
semgrep scan --config assets/semgrep-vibecoding.yml --config p/typescript --config p/react \
  --metrics=off --sarif -o security/05-statique/semgrep.sarif .
```

- `assets/semgrep-vibecoding.yml` contient les règles maison (clé secrète côté client, variable publique au nom de secret, HTML brut, garde de rôle côté client, filtre de tenant côté client, CORS joker, fetch d'URL de la requête, erreurs brutes).
- Les règles officielles du registre Semgrep sont sous licence d'usage interne : utilisables pour les apps de PA. Pour un livrable client qui les embarquerait, préférer Opengrep et les règles maison.
- `--metrics=off` évite d'envoyer des métriques d'usage.

## 5. Base Supabase

1. `python3 scripts/revue_sql.py supabase/migrations --sortie security/05-statique/revue-sql.md`
2. Dans le labo démarré : `supabase db advisors --type security > security/05-statique/advisors.txt`
3. **Lecture humaine de chaque policy** des tables qui portent des données personnelles. Le script repère des motifs ; il ne comprend pas une condition métier. Questions à poser pour chaque policy :
   - d'où vient le critère de tenant (`auth.uid()`, table d'appartenance, claim `app_metadata`) ou d'une valeur que le client contrôle ?
   - `USING` et `WITH CHECK` sont-ils tous deux présents pour l'écriture ?
   - la policy vise-t-elle `authenticated`, ou aussi `anon` (pas de `TO`) ?
   - une fonction appelée dans la policy est-elle `security definer` avec `search_path` fixé ?
4. Comparer avec le Dashboard de prod **en lecture**, si PA le fournit : policies ajoutées à la main hors migrations (écart de parité).

## 6. CI et conteneurs

- `zizmor .github/workflows/` : actions non épinglées par SHA, injection de template, permissions trop larges. Après la compromission de trivy-action en mars 2026, toute action tierce doit être épinglée par SHA complet.
- Trivy (≥ 0.76.2, image épinglée par digest) seulement si l'app a des Dockerfile ou des images.

## 7. Qualifier un signal

Les scripts et outils produisent des **signaux**. Avant d'en faire un finding, qualifier :

| Statut | Quand, en phase 5 |
|---|---|
| Confirmé | Le dépôt montre le défaut tel quel et il est exploitable sans hypothèse : secret dans l'historique, clé secrète dans le bundle, table exposée sans RLS, bucket public. |
| Probable | Le code montre le défaut, mais l'exploitation dépend d'une hypothèse (droits par défaut, réglage du Dashboard, route effectivement appelée). |
| Théorique | Motif de code sans démonstration (garde côté client sans preuve que le serveur manque de contrôle). |
| Faux positif | Écarté après lecture : dire pourquoi en une phrase. |

Format de `security/05-statique/synthese.md` :

```markdown
# Tests statiques : synthèse (<date>, commit <sha>)

| Signal | Catalogue | Statut | Preuve (fichier:ligne, sortie) | Suite |
|---|---|---|---|---|
| Table membres sans RLS | V-DB-01 | Confirmé | supabase/migrations/2026..._init.sql:2 | Finding (appsec-rapports) + TC-RLS-00x en phase 6 |

## Testé sans anomalie
## Non couvert (et pourquoi)
## Versions des outils
```

Toujours dire ce qui a été **testé sans anomalie** et ce qui **n'a pas été couvert** : sans cela, on ne peut pas juger la couverture.
