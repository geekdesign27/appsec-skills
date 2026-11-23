# Laboratoire Supabase + React/Vite (stack principale de PA)

Versions de référence vérifiées le 23.11.2026 : Supabase CLI 3.2.0, pgTAP 1.3.4 (voir `partage/referentiels.md`). Revérifier en début de mission.

## Sommaire
1. Prérequis
2. Monter le labo pas à pas
3. Ce que la CLI v3 change pour la sécurité du labo
4. Edge Functions, Storage, Realtime, Auth
5. Front Vite pointé sur le labo
6. Limites par rapport à la production (pour `04-labo.md`)
7. Dépannage

## 1. Prérequis

| Élément | Vérification |
|---|---|
| Docker (Docker Desktop sur Mac) | `docker info` répond |
| Supabase CLI ≥ 3 | `supabase --version` |
| Python 3 + PyYAML | `python3 -c "import yaml"` |
| Accès aux images Supabase | La CLI télécharge ses images depuis un registre public. Un réseau filtré ou un quota Docker Hub peut bloquer : le dire tôt plutôt que bricoler. |
| Aucun jeton de compte Supabase dans le shell | `echo $SUPABASE_ACCESS_TOKEN` vide. Le labo n'en a pas besoin. |

## 2. Monter le labo pas à pas

1. Depuis la racine de l'app : `supabase init` si `supabase/config.toml` n'existe pas.
2. Générer le gabarit d'identités, en reprenant les rôles réels (voir `01-inventaire.md`) :
   `python3 <skill>/scripts/labo_init.py gabarit . --roles owner,admin,member,viewer`
3. Adapter `security/labo/identites.yaml` au schéma réel : table des tenants, table d'appartenance ou `app_metadata`, tables sensibles à marquer. C'est l'étape qui demande de lire les migrations.
4. Générer le kit : `python3 <skill>/scripts/labo_init.py generer .`
5. Activer les seeds dans `supabase/config.toml` (le script affiche les lignes à ajouter) :
   ```toml
   [db.seed]
   enabled = true
   sql_paths = ["./seed.sql", "./seeds/*.sql"]
   ```
6. Monter : `security/labo/labo.sh up`
7. Remettre à zéro (migrations rejouées + seeds) : `security/labo/labo.sh reset`
8. Vérifier, avec une sonde sur une table marquée :
   `security/labo/labo.sh verifier --sonde public.<table>:<colonne>`
9. Arrêter : `security/labo/labo.sh down`

Critère de qualité n° 7 du profil : **une commande pour monter, une pour remettre à zéro.** `labo.sh up` et `labo.sh reset` le garantissent, à condition que les migrations se rejouent sans erreur. Si elles cassent, c'est un finding de robustesse (parité impossible à prouver) : le noter.

## 3. Ce que la CLI v3 change pour la sécurité du labo

- Toutes les commandes sont **locales par défaut**. Toucher un projet hébergé exige `--remote` et une confirmation.
- `--linked`, `--project-ref` et `--db-url` sont dépréciés au profit de `--remote`.
- `SUPABASE_YES` supprime les confirmations : ne jamais l'exporter dans le shell du labo (`labo.sh` refuse de tourner s'il l'est).
- `[inbucket]` est remplacé par `[local_smtp]` (Mailpit). `supabase start` échoue si l'ancienne section est encore là.
- Postgres 13 n'est plus accepté en local.
- `supabase db advisors --type security` lance les lints de sécurité en local : utile en phase 5.
- `supabase test db` lance les tests pgTAP en local : base des tests de régression RLS.

## 4. Edge Functions, Storage, Realtime, Auth

| Composant | Dans le labo | Attention |
|---|---|---|
| Edge Functions | `supabase functions serve --env-file security/labo/functions.env` | Le fichier ne contient que des valeurs de test. Une clé d'API tierce réelle (LLM, e-mail) n'y entre pas : la remplacer par un faux serveur ou une clé de test du fournisseur, avec l'accord de PA. |
| Storage | Buckets et policies créés par les migrations | Ajouter au seed un fichier marqué par tenant si l'app stocke des documents |
| Realtime | Actif dans la stack locale | La publication `supabase_realtime` doit venir des migrations, pas d'un réglage manuel |
| Auth | Config dans `config.toml` (`enable_signup`, `enable_confirmations`, redirections) | Reprendre les **mêmes** réglages que la prod, sinon le labo ment. Les écarts vont dans les limites. Les e-mails arrivent dans Mailpit. |

## 5. Front Vite pointé sur le labo

1. Créer `.env.local` (non versionné) avec l'URL et la clé publishable locales lues dans `supabase status -o env`.
2. `npm run dev` pour les parcours, `npm run build && npm run preview` pour tester le bundle construit (source maps, variables exposées).
3. Les en-têtes de sécurité configurés dans `vercel.json` ne sont **pas** servis par Vite : les vérifier en lecture du fichier, puis en observation passive sur l'environnement hébergé.

## 6. Limites par rapport à la production

À reporter dans `04-labo.md`, section « Limites ». Liste de départ :

| Pas reproduit dans le labo | Comment le couvrir |
|---|---|
| Réglages du Dashboard non versionnés (Auth, URL de redirection, SMTP, réseau) | Comparer avec la prod en lecture, ou demander une capture à PA |
| En-têtes et protection des previews Vercel | Lecture de `vercel.json` + observation passive |
| Secrets des Edge Functions et clés tierces réelles | Revue de code, faux serveur en labo |
| Volume de données réel et performance | Hors périmètre, ou test de charge séparé avec accord |
| Version exacte de Postgres et des extensions du projet hébergé | Comparer `supabase/config.toml` avec le Dashboard |
| Migrations appliquées à la main en prod | Comparer la liste des migrations locales et distantes en lecture |

## 7. Dépannage

| Symptôme | Piste |
|---|---|
| `supabase start` télécharge sans fin ou échoue sur un registre | Réseau filtré ou quota du registre. Tester depuis un autre réseau, ou pré-télécharger les images. Ne pas contourner un filtrage d'entreprise sans accord. |
| Seed refusé « comptes hors labo » | La base contient de vrais comptes : vérifier qu'on est bien sur la stack locale. |
| Connexion des identités en 400 | Mot de passe de `.env.lab` différent de celui du seed : relancer `labo_init.py generer` puis `labo.sh reset`. |
| Sonde vide pour une identité | Appartenance mal reliée dans `identites.yaml`, ou policy de lecture qui bloque aussi le propriétaire : c'est peut-être déjà un finding fonctionnel. |
