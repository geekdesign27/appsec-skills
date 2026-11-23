# Tests dynamiques : résultats du lot 1 (2026-11-23, cible labo http://127.0.0.1:54321)

- Version testée : migrations `20260901120000_init.sql` (sha256 fac5894dfbec…) et `20260915090000_storage_rpc.sql` (acd8bce9b61a…). Le dossier `chantier-pro` n'a pas de dépôt git propre : pas de commit applicatif à citer.
- Porte G2 : franchie le 2026-11-20 (journal, « go pour les lots 1 et 2 en labo local »).
- Labo vérifié vert avant le lot : `labo_verifier.py --sonde accidents:description` (6 identités connectées, chacune voit son marqueur). `labo.sh` non utilisé : CLI Supabase absente.
- Cohérence de la cible (matrice) : santé auth 200, requête sans clé refusée 401, jeton forgé refusé 401, filtre PostgREST respecté. Résultats probants.
- `03-plan.yaml` est vide : les cas ci-dessous (TC-L1-xx) sont dérivés du lot 1 de `03-plan.md` et des règles qu'il donne (admin : tout sur son entreprise ; membre : lire et déclarer ; lecteur : lire). À reprendre au format partagé par `appsec-cadrage-menaces`.

**En bref** : 6 échecs, 1 réussi, 3 bloqués sur 10 cas du lot 1. Matrice : 53 ÉCHEC, 6 écarts, 59 conformes sur 118 contrôles, dont 1 ÉCHEC non probant isolé (P-080, rejoué en P-124).

| TC | Titre | Statut | Preuve | Risques | Suite |
|---|---|---|---|---|---|
| TC-L1-01 | Une entreprise (ou un visiteur non connecté) lit les accidents d'une autre (REST) | Échec | P-004, P-001 (et P-002 à P-012, les 7 identités) | V-DB-02, V-AUTH-06 | Finding (appsec-rapports) |
| TC-L1-02 | Une entreprise crée, modifie, déplace ou supprime les accidents d'une autre | Réussi | P-068 à P-118 (refus 403 ou 0 ligne) | V-DB-03, V-DB-04 | Aucun ; voir écarts |
| TC-L1-03 | RPC `stats_entreprise` appelée avec l'id d'une autre entreprise | Échec | P-043 (et P-040 anon, P-041 à P-051) | V-DB-08, V-DB-05 | Finding |
| TC-L1-04 | Photos Storage d'une autre entreprise : listing et lecture | Échec | P-058, P-126 (anon par URL publique), P-053 à P-066 | V-DB-10 | Finding |
| TC-L1-05 | Dépôt d'un fichier dans le dossier Storage d'une autre entreprise | Bloqué | M-07 (`outils/lot1_manuel.json`) | V-DB-10 | Rejouer sur un vrai Supabase local |
| TC-L1-06 | Escalade verticale : se déclarer admin (sa ligne, une autre entreprise, sans compte) | Échec | P-083, P-119, P-124 (et P-084 à P-092) | V-DB-01, V-DB-09, V-AUTH-07, V-AUTH-01 | Finding |
| TC-L1-07 | Modifier ou supprimer les données d'une autre entreprise (membres, fiche entreprise) | Échec | P-120, P-121, P-122 (et M-05 anon) | V-DB-01, V-AUTH-06 | Finding |
| TC-L1-08 | Lire les membres et la fiche des autres entreprises | Échec | P-017, P-030 (matrice), lignes P-014 à P-038 | V-DB-01, V-DB-12 | Finding |
| TC-L1-09 | Realtime : a-membre reçoit les changements d'accidents de B | Bloqué | `outils/realtime.json` (pas de réponse 101 du serveur Realtime du labo) | V-DB-11 | Rejouer ; Probable par lecture des migrations |
| TC-L1-10 | Edge Function `export-pdf` sans JWT avec l'id de B | Bloqué | M-09, M-10 (404 : fonction non servie par le labo) | V-AUTH-05, V-API-01 | Rejouer avec `supabase functions serve` ; Probable par lecture du code |

Correspondance des tests manuels (`outils/lot1_manuel.py`) : M-01 → P-119, M-02 → P-120, M-03 → P-121, M-04 → P-122, M-05 → P-123 (pas de fiche, même constat que P-122 en anon), M-06 → P-124, M-08 → P-126.

## Échecs, en clair

1. **Lecture des accidents de toutes les entreprises** (P-004, P-001). La policy `accidents_select using (true)` laisse tout passer. N'importe quel compte, et même un visiteur avec la seule clé publishable, lit victimes, descriptions et gravités de toutes les entreprises. Donnée de santé au sens nLPD dans la vraie app.
2. **Photos d'accidents publiques** (P-058, P-126). Bucket `photos-accidents` public et policy de lecture sans tenant : une URL suffit, sans session ; le listing par dossier d'entreprise marche aussi.
3. **Statistiques de n'importe quelle entreprise** (P-043). `stats_entreprise` est SECURITY DEFINER, prend l'entreprise en paramètre et ne vérifie pas l'appartenance ; anon peut l'appeler.
4. **Prise de rôle admin** (P-083, P-119, P-124). La table `membres` n'a pas de RLS : un lecteur se met admin, un membre de A s'inscrit admin de B, un visiteur non connecté crée une appartenance admin. La garde admin d'`Admin.tsx` est seulement côté client.
5. **Modification des données d'une autre entreprise** (P-120, P-121, P-122). Sans RLS sur `membres` et `entreprises`, un compte de A modifie ou supprime les appartenances de B et réécrit la fiche de B ; anon peut aussi réécrire une fiche (M-05).

## Écarts fonctionnels (pas des findings, à confirmer avec PA)

- P-069, P-071, P-075, P-077 : admin et membre ne peuvent pas **déclarer** un accident (INSERT refusé, 403 RLS).
- P-095, P-101 : l'admin ne peut pas **modifier** un accident de son entreprise.
- Cause : `accidents` n'a qu'une policy SELECT. Le parcours « déclarer » ne peut pas marcher contre ces migrations, ou il passe par un chemin non vu. C'est aussi pour cela que TC-L1-02 résiste : l'écriture est fermée pour tout le monde, pas filtrée par entreprise. Le jour où une policy d'écriture sera ajoutée, TC-L1-02 devra être rejoué.

## Testé sans anomalie

- Écriture sur les accidents d'une autre entreprise : création, modification, déplacement vers l'autre tenant, suppression, pour les 7 identités (TC-L1-02).
- Lecture de ses propres données par chaque rôle (accidents, membres, entreprises, statistiques) : conforme à l'attendu.

## Non exécuté ou bloqué (et pourquoi)

- TC-L1-05 Storage, dépôt : le labo a coupé la connexion (code 0) sur `POST /storage/v1/object/...`. Ni réussite ni échec.
- TC-L1-09 Realtime : le serveur Realtime du labo ne répond pas (pas de 101). Par lecture : `accidents` est dans la publication `supabase_realtime` et sa policy SELECT est `using (true)`, donc la diffusion à tous est **Probable** (V-DB-11), pas confirmée.
- TC-L1-10 Edge Function `export-pdf` : 404, la fonction n'est pas servie par le labo. Par lecture : `verify_jwt = false`, clé secrète côté serveur, `entreprise_id` pris dans le corps, CORS `*` : fuite **Probable** (V-AUTH-05, V-API-01), pas confirmée.
- GraphQL (`/graphql/v1`) : 404, non exposé par le labo.
- Vues : aucune vue dans les migrations, non applicable.
- Inscription avec rôle forcé dans `user_metadata` : non exécuté, aucune policy ne lit `user_metadata` ; l'inscription ouverte (`enable_signup = true`, confirmation désactivée) relève du lot 2.
- P-080 (anon insère dans `membres` avec `user_id` = chaîne vide) : le labo a accepté une valeur qu'un vrai Postgres refuserait (22P02). Ligne non probante, rejouée avec `user_id` null en P-124 (Échec confirmé).

## État du labo après le lot (remise à zéro à faire par PA)

Le lot 1 a écrit dans le labo : lignes `membres` de test (rôle admin pour plusieurs identités, deux lignes sans utilisateur), `a-lecteur` passé admin (M-01), une ligne de test de B supprimée (M-03). `accidents` et les fichiers marqués sont intacts. Avant le lot 2 ou tout rejeu : `security/labo/labo.sh reset` (CLI Supabase requise), puis `labo.sh verifier --sonde accidents:description`.

## Limites (labo vs prod)

- Labo local, données synthétiques marquées uniquement ; aucune donnée réelle n'est apparue.
- Le labo renvoie toutes les colonnes même avec `select=` et a accepté un uuid vide : écarts de fidélité mineurs, sans effet sur les échecs confirmés (contre-vérification ciblée faite pour P-001 et P-004).
- Réglages de la prod (buckets, policies appliquées à la main, Realtime, fonctions déployées) non observés : à confirmer en revue statique et, si besoin, après la porte G3 en lecture seule.
