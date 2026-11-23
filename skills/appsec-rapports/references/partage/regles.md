# Règles non négociables (profil AppSec, section 3)

> Fichier partagé par toute la famille `appsec-*`. Ne pas le modifier dans un skill : la source est `partage/` à la racine du dépôt `appsec-skills`.

## 1. Cadre légal et éthique

1. **Aucun test sans autorisation écrite** du propriétaire de l'app et de l'infrastructure. Un mandat client exige des règles d'engagement signées.
2. Tester **uniquement** les apps de PA ou d'un client qui a signé les règles d'engagement. Jamais un service tiers (Supabase, Vercel, un fournisseur d'API) au-delà de l'usage normal de son propre compte.
3. Respecter les politiques de test des fournisseurs avant tout test sur leur infrastructure hébergée (voir section 5).
4. Données personnelles : appliquer la nLPD. Preuves caviardées. Aucune donnée réelle dans un rapport ni dans le contexte d'un agent.

### Base légale vérifiée

Art. 143bis CP (RS 311.0), « Accès indu à un système informatique », texte Fedlex consolidé au 01.11.2026, vérifié le 23.11.2026 :

- al. 1 : « Quiconque s'introduit sans droit, au moyen d'un dispositif de transmission de données, dans un système informatique appartenant à autrui et spécialement protégé contre tout accès de sa part, est, sur plainte, puni d'une peine privative de liberté de trois ans au plus ou d'une peine pécuniaire. »
- al. 2 : la mise en circulation de mots de passe, programmes ou données destinés à commettre l'infraction de l'al. 1 est aussi punissable.
- Source : https://www.fedlex.admin.ch/eli/cc/54/757_781_799/fr

Conséquence pratique : l'autorisation écrite est ce qui rend l'accès « avec droit ». Sans elle, on ne teste pas. Les scripts et preuves ne quittent pas le périmètre de la mission (al. 2).

## 2. Sécurité des tests

1. **Rien de destructif hors laboratoire.** Injection, fuzzing, déni de service, écriture massive, suppression : uniquement sur la stack locale isolée.
2. **Aucun secret de production** dans le laboratoire, le dépôt, les prompts ou les journaux d'un agent.
3. Environnement hébergé (preview, staging) : actions non destructives, comptes de test, et seulement si PA l'a autorisé explicitement pour cet environnement.
4. Production : observation passive uniquement (en-têtes, configuration publique, bundle JS public), sauf autorisation écrite spécifique.
5. Chaque test a un **niveau de risque** qui décide où il peut tourner :

| Niveau | Exemples | Environnements autorisés |
|---|---|---|
| faible | Lecture avec un compte de test, lecture d'en-têtes, lecture du bundle public | labo, staging (si G3), prod en observation passive |
| moyen | Écriture non destructive avec un compte de test, tentative d'escalade sur ses propres données de test | labo, staging (si G3) |
| destructif | Injection active, fuzzing, rafales, suppression, upload massif | **labo uniquement** |

En cas de doute sur le niveau, classer au niveau supérieur.

## 3. Portes de validation

| Porte | Avant de... | PA valide |
|---|---|---|
| G1 | Commencer | Périmètre, environnements, règles d'engagement |
| G2 | Exécuter | Plan de test priorisé et charge estimée |
| G3 | Sortir du laboratoire | Tout test sur un environnement hébergé |
| G4 | Diffuser | Rapport destiné à un tiers ou à un client |
| G5 | Modifier le code | Application des mitigations (le pack est une proposition, pas un ordre) |

Entre deux portes, l'expert avance seul et documente ses choix dans `security/journal.md`. Une porte franchie est notée dans le journal avec la date et la décision de PA, mot pour mot si possible.

## 4. Fiabilité des références

1. Ne jamais citer un identifiant ASVS, WSTG, CWE ou un article de loi **de mémoire**. Le récupérer dans la source officielle, par exemple avec `scripts/partage/ref_lookup.py`.
2. Avant chaque mission, vérifier que les versions des référentiels sont à jour (`references/partage/referentiels.md`) et noter la date de vérification dans le journal.
3. Distinguer **confirmé** (reproduit, preuve), **probable** (indices forts, non exploité), **théorique** (pattern de code, non démontré).
4. Si une source est injoignable, écrire « à vérifier » à côté de l'identifiant plutôt que de deviner.

## 5. Politiques des fournisseurs (vérifiées le 23.11.2026)

| Fournisseur | Ce qui est permis | Ce qui est interdit ou encadré | Source |
|---|---|---|---|
| Supabase | Tester ses propres projets (Auth, Database, Edge Functions, Storage, Realtime) sans accord préalable | DoS, flooding, attaques inter-tenant sur la plateforme, tout ce qui viole l'AUP. Faille dans un produit Supabase : signaler sous 24 h à security@supabase.com. Arrêter si Supabase le demande. | https://supabase.com/docs/guides/security/security-testing |
| Vercel | Plans **Pro et Enterprise** : tester ses propres apps hébergées | **Plan Hobby : pentest non autorisé.** Tests volumétriques : Enterprise uniquement, avec préavis via CSM ou AE. Infrastructure Vercel hors périmètre. | https://vercel.com/kb/guide/penetration-testing-on-vercel |

Revérifier ces pages à la porte G3 : elles changent.
