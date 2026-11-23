# Phase 1 : reconnaissance et inventaire → `security/01-inventaire.md`

Objectif : lister **tout ce qui peut être attaqué**, avant de penser aux attaques. On ne teste bien que ce qu'on a inventorié. Cette phase est passive : lecture du dépôt et du bundle construit en local, aucune requête active vers un environnement hébergé.

## 1. Surface d'attaque (stack React/Vite + Supabase + Vercel)

Lire le dépôt et remplir un tableau par catégorie. Commandes utiles entre parenthèses.

| Catégorie | Où regarder | À noter |
|---|---|---|
| Routes front | `src/` routeur, gardes de route (`grep -rn "Route\|createBrowserRouter"`) | Routes admin, routes cachées, gardes côté client seulement |
| Tables exposées PostgREST | `supabase/migrations/*.sql` (`create table`, `enable row level security`, `create policy`) | RLS active ou non, policies par commande, `using`/`with check` |
| Vues | `create view` | `security_invoker` présent ou non |
| Fonctions RPC | `create function`, `security definer`, `grant execute` | Appelables par `anon` ou `authenticated`, `search_path` fixé |
| Edge Functions | `supabase/functions/*/index.ts`, `supabase/config.toml` (`verify_jwt`) | Vérification JWT, usage de la clé secret, CORS |
| Storage | migrations `storage.buckets`, policies `storage.objects` | Buckets publics, chemins devinables |
| Realtime | `supabase.channel(`, publications `supabase_realtime` | Tables publiées, filtres |
| Auth | `config.toml` section auth, appels `signUp`, OAuth, magic link | Inscription ouverte, confirmation e-mail, URLs de redirection, MFA |
| Variables d'environnement | `.env*`, `vite.config.*`, `VITE_*` | Secrets avec préfixe public |
| Services tiers | `fetch(` vers des domaines externes, SDK | Données envoyées, clés |
| Fonctions IA | appels LLM, RAG, outils d'agent | Voir `ia-llm.md` |
| Hébergement | `vercel.json`, en-têtes, réécritures, protection des previews | CSP, en-têtes, previews publiques |

## 2. Bundle JS

Construire en local (`npm run build`) et analyser `dist/`, plutôt que télécharger le bundle de prod. Rechercher :

- URLs d'API et de projets Supabase ;
- clés : `sb_publishable_` (normal), `sb_secret_` ou JWT `service_role` (critique) ;
- routes et noms de fonctions non visibles dans l'interface ;
- fichiers `*.map` (source maps) générés.

Si le bundle de prod doit être consulté, c'est de l'observation passive autorisée (règles, section 2.4) : un simple téléchargement, rien de plus.

## 3. Rôles et tenants

Tableau des rôles réels de l'app (pas ceux du profil) : nom, comment il est attribué (table, claim `app_metadata`, `user_metadata`), qui peut le modifier. Signaler tout rôle stocké dans `user_metadata` ou dans une colonne modifiable par l'utilisateur (V-DB-06, V-DB-09).

Décrire le modèle multi-tenant : colonne de tenant, table d'appartenance, comment le tenant courant est déterminé.

## 4. Dépendances et outillage

- Lockfile présent ou non, scripts `postinstall`.
- Paquets récents, peu téléchargés ou au nom proche d'un paquet connu (V-SC-01) : les lister pour la phase 5, sans conclure.
- Serveurs MCP et extensions configurés dans l'environnement de dev (`.mcp.json`, `.claude/`), en particulier un MCP Supabase pointé sur la prod (V-AI-01).
- CI : workflows, secrets utilisés, actions non épinglées.

## 5. Autres plateformes

| Plateforme | Inventaire spécifique |
|---|---|
| Odoo | Modules custom, `ir.model.access.csv`, `ir.rule`, contrôleurs `auth='public'`, appels `sudo()`, portail |
| WeWeb | Collections et leurs sources, workflows front contenant des appels authentifiés, backend réel (Supabase, Xano) |
| WordPress | Version, plugins et thèmes avec versions, comptes admin, `xmlrpc.php`, REST API utilisateurs |
| Convex | Fonctions `query`/`mutation`/`action` publiques vs `internal*`, appels `ctx.auth.getUserIdentity()` |

## 6. Sortie

`01-inventaire.md` contient les tableaux ci-dessus, et une liste « **Signaux à confirmer** » qui renvoie aux identifiants du catalogue (V-DB-02, V-SEC-01...) avec le statut **théorique**. Rien n'est confirmé à ce stade.
