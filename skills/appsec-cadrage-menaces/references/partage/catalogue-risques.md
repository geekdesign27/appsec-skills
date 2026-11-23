# Catalogue des risques typiques des apps vibecodées (profil AppSec, section 5)

> Fichier partagé par toute la famille `appsec-*`. Source : `partage/` à la racine du dépôt `appsec-skills`.
> Ce catalogue alimente la modélisation des menaces et le plan de test. Chaque entrée devient au moins un cas de test.

## Sommaire

1. Supabase et base de données (V-DB)
2. Secrets et configuration (V-SEC)
3. Authentification et autorisation applicative (V-AUTH)
4. Front, API et robustesse (V-FE, V-API, V-LOG)
5. Chaîne d'approvisionnement et pipeline IA (V-SC, V-AI)
6. Fonctions IA dans l'app
7. Autres plateformes

## 1. Supabase et base de données

| ID | Risque | Signal à chercher |
|---|---|---|
| V-DB-01 | RLS désactivée sur une table exposée | Advisors Supabase, `pg_tables.rowsecurity = false` |
| V-DB-02 | Policy trop large | `using (true)`, policy pour `public` au lieu de `authenticated` |
| V-DB-03 | Policy SELECT présente mais INSERT/UPDATE/DELETE absentes ou laxistes | Policies incomplètes par commande |
| V-DB-04 | `WITH CHECK` absent : un utilisateur réécrit `tenant_id` ou `owner_id` | UPDATE qui change le tenant |
| V-DB-05 | Tenant déduit d'une donnée fournie par le client au lieu de `auth.uid()` ou d'un claim fiable | Paramètre `tenant_id` dans la requête |
| V-DB-06 | Policy basée sur `user_metadata` (modifiable par l'utilisateur) au lieu de `app_metadata` | `auth.jwt() -> 'user_metadata'` |
| V-DB-07 | Vue sans `security_invoker` qui contourne RLS | Vues dans le schéma exposé |
| V-DB-08 | Fonction `SECURITY DEFINER` appelable en RPC sans contrôle, `search_path` non fixé | `pg_proc.prosecdef`, droits EXECUTE |
| V-DB-09 | Mass assignment : colonnes sensibles modifiables (`role`, `is_admin`, `plan`) | Privilèges de colonne, UPDATE direct PostgREST |
| V-DB-10 | Buckets Storage publics ou policies Storage laxistes | `storage.objects` policies, URLs devinables |
| V-DB-11 | Realtime qui diffuse des lignes d'autres tenants | Canaux postgres_changes, broadcast, presence |
| V-DB-12 | Schéma exposé trop large (tables internes dans `public`) | Config API, OpenAPI exposé |

## 2. Secrets et configuration

| ID | Risque | Signal |
|---|---|---|
| V-SEC-01 | Clé secret / `service_role` dans le bundle JS | Recherche dans `dist/`, sources maps |
| V-SEC-02 | Secret exposé par préfixe public (`VITE_`, `NEXT_PUBLIC_`) | Variables d'environnement |
| V-SEC-03 | `.env` versionné ou secret dans l'historique git | Scanner de secrets sur tout l'historique |
| V-SEC-04 | Secrets dans les transcripts ou journaux d'agents IA | Dossiers de sessions, logs CI |
| V-SEC-05 | Source maps publiques en production | `*.map` accessibles |
| V-SEC-06 | Deployments preview publics avec données ou variables de prod | Config Vercel, protection des previews |

## 3. Authentification et autorisation applicative

| ID | Risque | Signal |
|---|---|---|
| V-AUTH-01 | Autorisation seulement côté client (boutons masqués, garde de route React) | Appel API direct qui passe |
| V-AUTH-02 | Inscription ouverte alors que l'app est sur invitation | Endpoint signup actif |
| V-AUTH-03 | Confirmation d'e-mail désactivée, politique de mot de passe faible, pas de MFA admin | Config Auth |
| V-AUTH-04 | Liste d'URLs de redirection trop large (magic link, OAuth) | Wildcards, vol de jeton |
| V-AUTH-05 | Edge Function sans vérification JWT ou qui fait confiance à un id fourni | `verify_jwt = false`, usage de la clé secret |
| V-AUTH-06 | IDOR / BOLA : accès à l'objet d'un autre en changeant un identifiant | Matrice d'autorisation |
| V-AUTH-07 | Escalade verticale : un membre exécute une action admin | Matrice d'autorisation |

## 4. Front, API et robustesse

| ID | Risque | Signal |
|---|---|---|
| V-FE-01 | XSS via `dangerouslySetInnerHTML`, rendu Markdown ou HTML de contenu utilisateur ou LLM | Grep, tests de charge utile |
| V-FE-02 | CSP absente ou permissive, en-têtes de sécurité manquants | Réponse HTTP |
| V-API-01 | CORS `*` sur des endpoints authentifiés | Edge Functions, API custom |
| V-API-02 | Pas de limitation de débit (auth, RPC, endpoints LLM coûteux) | Rafales de requêtes en labo |
| V-API-03 | Erreurs verbeuses (stack traces, erreurs Postgres détaillées) | A10:2025 |
| V-API-04 | Upload de fichiers sans contrôle de type, taille, contenu | Storage, Edge Functions |
| V-API-05 | SSRF via une fonction qui récupère une URL fournie | A01:2025 |
| V-LOG-01 | Pas de journal d'audit des actions sensibles, pas d'alerte | A09:2025 |

## 5. Chaîne d'approvisionnement et pipeline IA

| ID | Risque | Signal |
|---|---|---|
| V-SC-01 | Paquet halluciné par le LLM ou typosquat (slopsquatting) | Paquets récents, peu téléchargés, nom proche d'un connu |
| V-SC-02 | Dépendances vulnérables ou abandonnées | osv-scanner, npm audit, EPSS/KEV |
| V-SC-03 | Lockfile absent, scripts `postinstall` non maîtrisés | Dépôt |
| V-SC-04 | Serveurs MCP ou extensions non vérifiés dans l'environnement de dev | Config Claude Code |
| V-AI-01 | Agent de dev avec accès à la base de production | MCP Supabase pointé sur la prod |
| V-AI-02 | Injection de prompt via contenu du dépôt, d'issues ou de pages lues par l'agent | Fichiers d'instructions, contenus tiers |
| V-AI-03 | « Correctif » IA qui désactive RLS ou un contrôle pour faire passer un test | Diff des migrations |
| V-AI-04 | Tests générés par IA qui ne couvrent que le chemin nominal | Absence de tests négatifs d'autorisation |

## 6. Fonctions IA dans l'app (si présentes)

Appliquer l'OWASP Top 10 for LLM Applications **2026** (voir `referentiels.md`) : injection de prompt directe et indirecte, fuite d'informations sensibles, agentivité excessive (outils trop puissants), exposition du contexte caché (dont le prompt système), faiblesses des embeddings et du RAG (cloisonnement par tenant), consommation non bornée (coûts), traitement non sûr des sorties. Et l'Agentic Top 10 2026 si l'app embarque des agents qui agissent.

## 7. Autres plateformes

- **Odoo** : droits d'accès (`ir.model.access`), règles d'enregistrement (`ir.rule`) multi-société, usage de `sudo()`, contrôleurs HTTP `auth='public'`, portail.
- **WeWeb** : autorisation réellement appliquée côté backend, données exposées dans les collections, secrets dans les workflows front.
- **WordPress** : plugins et thèmes vulnérables, `xmlrpc.php`, énumération des utilisateurs, comptes admin, mises à jour (outil : WPScan).
- **Convex** : contrôle d'identité dans chaque query/mutation, fonctions publiques vs internes.
