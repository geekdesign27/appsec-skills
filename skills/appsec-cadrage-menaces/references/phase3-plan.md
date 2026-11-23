# Phase 3 : plan de test → `security/03-plan.md` + `security/03-plan.yaml`

Objectif : transformer les menaces en **cas de test priorisés, chiffrés et rattachés aux référentiels**, que PA valide à la porte G2. C'est le plan de contrôle de l'audit : on sait avant de commencer ce qu'on vérifie, comment, où et combien de temps.

## 1. Retenir les exigences ASVS applicables

1. Extraire les exigences du niveau choisi :
   `python3 scripts/plan_tool.py asvs --niveau 2 > security/03-asvs.csv`
2. Marquer chaque ligne `applicable` = oui ou non, avec une raison courte pour les non (« pas de WebRTC », « pas d'OAuth tiers »). Le script ajoute ces colonnes vides.
3. Les chapitres souvent hors périmètre sur la stack de PA : V17 WebRTC ; V10 OAuth et OIDC si seul Supabase Auth par e-mail est utilisé. Les chapitres presque toujours centraux : V8 Authorization, V6 Authentication, V7 Session Management, V13 Configuration, V14 Data Protection, V4 API and Web Service.

Ne jamais citer une exigence sans l'avoir lue dans ce fichier ou via `ref_lookup.py`.

## 2. Écrire les cas de test

Format partagé : `references/partage/formats.md`, section 1. Règles :

- Partir des menaces cotées (TM-xxx), de la plus haute à la plus basse.
- Chaque menace Critique ou Élevée a au moins un cas de test.
- Chaque entrée du catalogue retenue en phase 2 a au moins un cas de test.
- Champ `referentiels` : ASVS et WSTG vérifiés avec `ref_lookup.py`, Top 10:2025, API:2023 si API, CWE vérifié.
- `risque_du_test` et `environnements_autorisés` doivent être cohérents : `destructif` implique `[labo]` uniquement.
- Prévoir des **tests négatifs** (ce qui doit être refusé), pas seulement le chemin nominal (V-AI-04).
- Les marqueurs de preuve (`SECRET-TENANT-B-001`) rendent une fuite indiscutable : les citer dans `critere_echec`.

## 3. Prioriser en lots

Ordre par défaut, du plus rentable au moins rentable sur une app vibecodée :

| Lot | Contenu | Pourquoi d'abord |
|---|---|---|
| 1 | RLS et policies (revue + pgTAP), secrets (bundle, historique git), **matrice d'autorisation** par API directe, isolation multi-tenant | Ce sont les failles que les assistants de code reproduisent en série, et les plus graves |
| 2 | Authentification et session, configuration (Auth, Storage, Edge Functions, en-têtes, CORS), dépendances, Storage, Realtime | Fréquent, souvent rapide à corriger |
| 3 | Logique métier, injection et entrées, upload, SSRF, fonctions IA, robustesse et erreurs, journalisation | Plus long, plus spécifique à l'app |

Pour une **mission express** (petite app, peu de données), le lot 1 suffit souvent : le dire explicitement et lister ce qui n'est pas couvert.

## 4. Classer chaque test

| Champ | Valeurs | Usage |
|---|---|---|
| `mode` | automatique, semi, manuel | Les automatiques deviendront des tests de régression |
| `risque_du_test` | faible, moyen, destructif | Décide l'environnement |
| `environnements_autorises` | labo, staging, prod | prod = observation passive seulement |
| `priorite` | P0 à P3 | Ordre dans le lot |
| `effort_min` | minutes | Somme = charge du lot |

## 5. Estimer, mesurer la couverture, valider

1. Valider le fichier : `python3 scripts/plan_tool.py valider security/03-plan.yaml --menaces security/02-menaces.md`
   Le script vérifie les champs obligatoires, les formats d'identifiants, l'existence des identifiants ASVS et WSTG dans les sources officielles, la cohérence risque et environnement, et que chaque TM citée existe.
2. Calculer charge et couverture : `python3 scripts/plan_tool.py couverture security/03-plan.yaml --asvs security/03-asvs.csv`
   Sortie : charge par lot, nombre de cas par priorité, couverture ASVS = exigences applicables couvertes par au moins un cas / exigences applicables.
3. Rédiger `03-plan.md` : niveau ASVS, lots et ordre, charge, couverture attendue, ce qui n'est pas couvert et pourquoi.

## 6. Porte G2

Présenter à PA en peu de lignes : nombre de cas, lots, charge totale, couverture ASVS attendue, tests qui sortiraient du labo (ils exigeront aussi G3). Attendre la validation, la noter au journal mot pour mot. Puis passer le relais à `appsec-labo`.
