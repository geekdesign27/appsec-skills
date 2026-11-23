# Formats partagés (profil AppSec, sections 8, 9.4, 11, 12)

> Fichier partagé par toute la famille `appsec-*`. Source : `partage/` à la racine du dépôt `appsec-skills`.
> Reprendre ces formats **à l'identique**. Les champs entre `<...>` se remplissent avec des valeurs vérifiées dans la source officielle, jamais de mémoire.

## Sommaire

1. Cas de test (section 8)
2. Finding (section 9.4)
3. Pack de mitigation `mitigation-pack.yaml` (section 11.2)
4. `PROMPT-IA.md` (section 11.3)
5. Plan de retest `retest-plan.yaml` (section 12)

---

## 1. Cas de test

```yaml
id: TC-AUTHZ-012
titre: Un membre du tenant A ne peut pas lire les audits du tenant B via l'API
objectif: Vérifier l'isolation multi-tenant en lecture sur la table audits
menaces: [TM-004]
referentiels:            # identifiants à récupérer dans les sources officielles, jamais de mémoire
  asvs: "<id ASVS 5.0>"
  wstg: "<id WSTG>"
  top10: "A01:2025"
  api: "API1:2023"
  cwe: "CWE-639"
cible: "PostgREST /rest/v1/audits"
preconditions: "Labo seedé, identités a-member et b-owner, audit marqué SECRET-TENANT-B-001"
mode: automatique          # automatique | semi | manuel
outillage: "Playwright + client supabase-js avec le JWT de a-member"
etapes:
  - "Se connecter en a-member, récupérer le JWT"
  - "GET /rest/v1/audits?select=* sans filtre"
  - "GET /rest/v1/audits?id=eq.<id audit B>"
resultat_attendu_securise: "Aucune ligne du tenant B retournée"
critere_echec: "Présence de SECRET-TENANT-B-001 dans une réponse"
preuves: "Requête, réponse caviardée, horodatage, commit testé"
risque_du_test: faible     # faible | moyen | destructif (destructif = labo uniquement)
environnements_autorises: [labo]
priorite: P1
effort_min: 10
regression: "Oui : test pgTAP + test Playwright en CI"
```

`plan.yaml` est une liste de cas de test dans ce format.

---

## 2. Finding

```markdown
# F-007 : Lecture inter-tenant de la table audits

- Statut : Confirmé
- Sévérité : Critique (CVSS 4.0 : <vecteur complet> = <score>)
- Priorité : P0
- Catégories : A01:2025, API1:2023, CWE-639
- Exigences ASVS non satisfaites : <ids>
- Tests : TC-AUTHZ-012 (échec)
- Actif : table public.audits, policy "audits_select"

## Constat
Une phrase par fait. Ce qui a été observé, où, quand.

## Preuve
Requête et réponse caviardées, capture, commit testé.

## Impact
Ce qu'un attaquant obtient, pour qui, avec quelles conséquences (dont nLPD).

## Cause racine
Ex. : policy qui filtre sur un tenant_id fourni par le client.

## Recommandation (résumé)
Renvoi vers M-007 du pack de mitigation.

## Limites
Ce qui n'a pas été testé ou reste incertain.
```

Chaque finding a une preuve, une cause racine, une mesure (M-xxx) et au moins un retest (RT-xxx).

---

## 3. Pack de mitigation : `mitigation-pack.yaml`

Objectif : donner à une IA de développement (Claude Code, `dev-senior`) tout ce qu'il faut pour **analyser** puis **proposer** une intégration propre, sans appliquer à l'aveugle.

```yaml
contexte:
  app: "<nom>"
  stack: "React/Vite/TS, Supabase, Vercel"
  commit_teste: "<sha>"
  date: "2026-11-23"
  contraintes_globales:
    - "Ne jamais désactiver RLS pour faire passer un test"
    - "Ne pas casser les parcours listés dans tests/e2e"
    - "Migrations SQL réversibles uniquement"
mesures:
  - id: M-007
    findings: [F-007]
    priorite: P0
    titre: "Isoler la lecture des audits par tenant côté base"
    niveau_stop: T          # S | T | O | P
    actifs:
      - "supabase/migrations/*audits*.sql"
      - "policy public.audits.audits_select"
    cause_racine: "Filtre sur tenant_id fourni par le client"
    options:
      - id: A
        description: "Policy basée sur l'appartenance du user au tenant via une table membres"
        avantages: ["Robuste", "Testable en pgTAP"]
        inconvenients: ["Jointure à indexer"]
        recommandee: true
      - id: B
        description: "Claim tenant dans app_metadata du JWT"
        avantages: ["Performant"]
        inconvenients: ["Gestion du changement de tenant"]
    guidage_implementation:
      - "Créer une fonction SQL stable security definer avec search_path fixé, qui retourne les tenants du user"
      - "Réécrire USING et WITH CHECK pour SELECT, INSERT, UPDATE, DELETE"
    ne_pas_faire:
      - "Filtrer seulement côté front"
      - "Utiliser user_metadata"
    criteres_acceptation:
      - "RT-007a et RT-007b passent"
      - "Aucune régression des tests e2e"
    tests_retest: [RT-007a, RT-007b]
    dependances: []
    effort_estime: "2 h"
    retour_arriere: "Migration down fournie"
```

Niveaux S-T-O-P : S substitution ou suppression de la fonction risquée, T mesure technique (RLS, validation serveur, CSP), O mesure organisationnelle (revue, processus de release), P mesure personnelle (former, règles dans le harnais).

---

## 4. `PROMPT-IA.md`

Accompagne le pack, généré à chaque mission. Contenu attendu :

1. Rôle de l'IA réceptrice : analyser le pack au regard du code réel.
2. Étapes demandées : vérifier chaque cause racine dans le code, signaler les écarts, proposer un plan d'intégration ordonné (dépendances, regroupements par migration), estimer les risques de régression.
3. Interdits : appliquer sans validation de PA, contourner un contrôle, désactiver RLS, élargir des droits.
4. Livrable attendu : plan d'intégration + diffs proposés + tests ajoutés, en attente de la porte G5.

---

## 5. Plan de retest : `retest-plan.yaml`

```yaml
- id: RT-007a
  mesure: M-007
  finding: F-007
  rejoue: TC-AUTHZ-012
  type: automatique        # automatique | manuel
  forme: "pgTAP"            # pgTAP | Playwright | Nuclei | Semgrep | script | manuel
  resultat_attendu: "0 ligne du tenant B pour a-member"
  integre_ci: true
- id: RT-007b
  mesure: M-007
  finding: F-007
  rejoue: "Variante écriture : UPDATE tenant_id vers B"
  type: automatique
  forme: "Playwright"
  resultat_attendu: "Refus 401/403 ou 0 ligne modifiée"
  integre_ci: true
```

Règles :

1. Chaque mesure a **au moins un test qui échouait avant** et doit passer après.
2. Ajouter une **variante** (autre commande SQL, autre rôle, autre canal) pour éviter le correctif qui ne couvre que le cas exact.
3. Rejouer aussi les tests voisins (régression).
4. Statut final par finding : corrigé, partiellement corrigé, non corrigé, risque accepté (avec nom et date de la décision).
5. Les tests automatisables rejoignent la CI ; les règles statiques (Semgrep ou Opengrep, scanner de secrets) rejoignent le pre-commit ou la CI.
