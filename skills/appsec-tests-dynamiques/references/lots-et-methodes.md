# Phase 6 : lots de tests et méthodes

Repris et complété du skill `pentest-saas-vibecoding` (fichier « tests Supabase et Convex »), que cette famille remplace.
Chaque test a un niveau de risque (faible, moyen, destructif) qui décide où il tourne : `partage/regles.md`, section 2.

## Sommaire
1. Avant de lancer
2. Lot 1 : autorisation et isolation multi-tenant
3. Lot 2 : authentification, session, configuration
4. Lot 3 : logique métier, entrées, API, robustesse
5. Fonctions IA
6. Autres plateformes
7. Conditions d'arrêt

## 1. Avant de lancer

1. Porte G2 franchie et notée au journal (plan validé).
2. Labo vérifié vert : `security/labo/labo.sh verifier --sonde <table>:<colonne>`.
3. Cible = labo local. Tout test sur un environnement hébergé exige la porte **G3** et la politique de l'hébergeur (Vercel Hobby : non ; Pro/Enterprise : non volumétrique). Supabase : pas de DoS, pas d'attaque de la plateforme.
4. Noter le commit testé : `git rev-parse --short HEAD`.

## 2. Lot 1 : autorisation et isolation multi-tenant (le plus rentable)

### 2.1 Matrice d'autorisation par API directe

```bash
python3 scripts/matrice_autorisation.py gabarit --sortie security/06-dynamique/matrice.yaml
# adapter : tables, colonne de tenant, colonne marquée, RPC, buckets, et surtout « attendu » par rôle
python3 scripts/matrice_autorisation.py executer security/06-dynamique/matrice.yaml
security/labo/labo.sh reset     # le test écrit des lignes de test : remettre à zéro après
```

`attendu` décrit la règle métier **sur son propre tenant**. Sur l'autre tenant, tout doit être refusé. Remplir `attendu` à partir du plan et de PA, pas à partir de ce que l'app fait : sinon on valide le bug.

Lecture des résultats : **ÉCHEC** = faille (accès qui aurait dû être refusé) ; **écart** = refus d'une action attendue (bug fonctionnel ou règle mal comprise, à vérifier avec PA) ; **OK** = conforme.

### 2.2 Les autres canaux de l'isolation

La matrice couvre REST, RPC et Storage. Compléter à la main ou par script :

| Canal | Test | Signal d'échec |
|---|---|---|
| Realtime | S'abonner en a-member à `postgres_changes` sur la table, puis insérer une ligne en b-owner | a-member reçoit l'événement du tenant B |
| Vues | `GET /rest/v1/<vue>` en a-member et en anon | Lignes ou marqueurs de B |
| GraphQL (`/graphql/v1`) si actif | Même requête que REST | Données de B |
| Edge Functions | Appel sans JWT, avec le JWT de A en passant l'id de B | Réponse avec des données de B |
| Exports, liens partagés, PDF | Générer un lien en A, l'ouvrir en B ou sans session | Contenu accessible |
| URL signées Storage | Durée de vie, réutilisation par un autre compte | Lien valable trop longtemps ou partageable |

Exemple Realtime (Node ou navigateur du labo, avec les identités de `identites.md`) :

```js
const a = createClient(URL, PUBLISHABLE); await a.auth.signInWithPassword({ email: 'a-member@labo.test', password: MDP })
a.channel('t').on('postgres_changes', { event: 'INSERT', schema: 'public', table: '<table>' }, p => console.log('REÇU', p.new)).subscribe()
// puis, avec b-owner, insérer une ligne marquée SECRET-TENANT-B-RT-001 : si a-member la reçoit, c'est un ÉCHEC
```

### 2.3 Escalade verticale

- `PATCH` de sa propre ligne de profil vers un rôle supérieur (`role`, `is_admin`, `plan`).
- Inscription avec un rôle forcé dans `options.data` (user_metadata) : vérifier que l'app ne s'y fie pas.
- Appel direct des RPC et Edge Functions réservées à l'admin, en membre.

## 3. Lot 2 : authentification, session, configuration

| Test | Méthode (labo) | Signal d'échec |
|---|---|---|
| Inscription ouverte | `POST /auth/v1/signup` avec un e-mail `@labo.test` | Compte créé alors que l'app est sur invitation |
| Confirmation d'e-mail | Se connecter avant confirmation (Mailpit) | Session obtenue |
| Énumération de comptes | Comparer messages et temps : login, reset, signup, e-mail existant ou non | Différence exploitable |
| Rejeu de JWT | Rejouer le JWT après `signOut` | Accès encore accepté (noter la durée de vie du JWT) |
| Révocation | Désactiver un compte de test, réutiliser son refresh token | Nouvelle session obtenue |
| Redirections | Magic link ou OAuth avec `redirect_to` vers un domaine non prévu | Redirection acceptée |
| MFA admin | Se connecter en admin sans second facteur | Accès aux fonctions admin |
| Limitation de débit login | Rafale de tentatives **en labo uniquement** | Aucun plafond (noter que la prod a ses propres réglages) |
| En-têtes | Lecture des réponses de l'app Vite (`npm run preview`) ; en-têtes Vercel en observation passive (G3) | CSP absente, HSTS absent, iframe possible |

## 4. Lot 3 : logique métier, entrées, API, robustesse

Tout ce lot est **labo uniquement** dès qu'il envoie des charges actives.

| Domaine | Méthode | Outil |
|---|---|---|
| Logique métier | Sauter une étape, modifier un objet clos, dépasser un quota, actions concurrentes (conditions de course) | Script ou Playwright/Dev Browser |
| XSS stockée | Enregistrer `<img src=x onerror=alert(document.domain)>` dans un champ texte, l'afficher dans un autre compte | Playwright, vérifier l'exécution |
| Injection SQL | Paramètres des RPC et fonctions avec SQL dynamique | sqlmap, **labo uniquement** |
| Upload | Type, taille, extension double, SVG avec script, chemin `../` | Script |
| SSRF | Fonction qui récupère une URL : `http://127.0.0.1`, `http://169.254.169.254` | Script |
| Erreurs | Provoquer des erreurs (types invalides, filtres PostgREST cassés) | Réponse avec détail Postgres ou trace |
| Fuzzing API | Schéma OpenAPI de PostgREST : `GET /rest/v1/` avec la clé publishable | Schemathesis 4.x (`schemathesis run <url du schéma>`, en-têtes apikey et Authorization : voir `schemathesis run --help` de la version installée), labo |
| Scan DAST | App Vite locale | ZAP baseline (`zap-baseline.py -t http://127.0.0.1:5173`), puis Nuclei avec des modèles ciblés |
| Volume | Requêtes sans limite, pagination absente | Labo, sans saturer la machine |

## 5. Fonctions IA

| Test | Méthode | Signal d'échec |
|---|---|---|
| Injection directe | Prompts qui demandent d'ignorer les consignes et de lire un autre tenant | Données d'un autre tenant, ou action hors périmètre |
| Injection indirecte | Document ou champ marqué contenant des instructions, traité par l'IA | L'IA exécute l'instruction |
| Cloisonnement RAG | Question dont la réponse est un marqueur du tenant B, posée en A | Le marqueur apparaît |
| Contexte caché | Demander le prompt système, les outils, les variables | Restitution du contexte interne |
| Sortie non traitée | Faire produire du HTML ou Markdown actif | Script exécuté à l'affichage |
| Coût | Boucle d'appels en labo avec un faux fournisseur | Aucun plafond par utilisateur |

Pas d'appel à un vrai fournisseur LLM avec des données de test sans l'accord de PA (coût, données envoyées à un tiers).

## 6. Autres plateformes

- **Convex** : appeler chaque query et mutation publique directement, en A avec des ids de B ; vérifier `ctx.auth.getUserIdentity()` et le filtrage ; tenter d'appeler une fonction `internal*` depuis le client.
- **Odoo** : en utilisateur de la société A, ouvrir les enregistrements de la société B par URL et par RPC (`/web/dataset/call_kw`) ; contrôleurs `auth='public'` ; portail.
- **WordPress** : WPScan en labo, REST `/wp-json/wp/v2/users`, rôles éditeur et auteur.
- **WeWeb** : tester le **backend** directement, comme Supabase ; l'interface WeWeb ne protège rien.

## 7. Conditions d'arrêt

Arrêter immédiatement et noter au journal si :

1. Une donnée réelle apparaît (nom, e-mail, donnée de santé non marquée) : ne pas la copier, caviarder, informer PA.
2. La cible n'est plus locale ou ne correspond plus à l'hôte autorisé.
3. Un test dégrade la machine ou un service partagé.
4. Une faille touche un produit Supabase lui-même : la signaler à Supabase sous 24 h (politique de test, `partage/regles.md`).
