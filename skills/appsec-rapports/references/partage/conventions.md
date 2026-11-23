# Conventions partagées (profil AppSec, sections 6.11, 6.12, 9)

> Fichier partagé par toute la famille `appsec-*`. Source : `partage/` à la racine du dépôt `appsec-skills`.

## 1. Arborescence standard d'une mission

Chaque phase produit un livrable nommé, stocké dans le dépôt de l'app sous `security/`. Le script `scripts/partage/init_security.py` crée cette arborescence.

```
security/
  00-cadrage.md
  01-inventaire.md
  02-menaces.md          (DFD Mermaid + STRIDE)
  03-plan.md             (+ plan.yaml machine-readable)
  04-labo.md
  05-statique/
  06-dynamique/
  07-findings/F-001.md ...
  08-rapports/
  09-mitigation/mitigation-pack.yaml + PROMPT-IA.md
  10-retest/retest-plan.yaml + resultats/
  journal.md             (chronologie, décisions, écarts)
```

## 2. Phases et skills

| Phase | Livrable | Skill |
|---|---|---|
| 0 Cadrage et autorisation | `00-cadrage.md` | `appsec-cadrage-menaces` |
| 1 Reconnaissance et inventaire | `01-inventaire.md` | `appsec-cadrage-menaces` |
| 2 Modélisation des menaces | `02-menaces.md` | `appsec-cadrage-menaces` |
| 3 Plan de test | `03-plan.md`, `plan.yaml` | `appsec-cadrage-menaces` |
| 4 Laboratoire | `04-labo.md` + fichiers | `appsec-labo` |
| 5 Tests statiques | `05-statique/` | `appsec-tests-statiques` |
| 6 Tests dynamiques | `06-dynamique/` | `appsec-tests-dynamiques` |
| 7 Analyse et cotation | `07-findings/F-xxx.md` | `appsec-rapports` |
| 8 Rapports | `08-rapports/` | `appsec-rapports` |
| 9 Pack de mitigation | `09-mitigation/` | `appsec-mitigation-retest` |
| 10 Retest et capitalisation | `10-retest/` | `appsec-mitigation-retest` |

Le skill `appsec-chef-de-mission` orchestre l'ensemble, tient le journal et les portes.

## 3. Identifiants

| Préfixe | Objet |
|---|---|
| TM-xxx | Menace |
| TC-<DOMAINE>-xxx | Cas de test (ex. TC-AUTHZ-012) |
| F-xxx | Finding |
| M-xxx | Mesure de mitigation |
| RT-xxx | Test de retest |

- Numérotation sur 3 chiffres, sans réutiliser un numéro supprimé.
- Domaines de cas de test conseillés : AUTHZ (autorisation), TENANT (isolation multi-tenant), AUTHN (authentification et session), RLS, SEC (secrets), CONF (configuration), INJ (injection et entrées), FE (front), API, LOGIC (logique métier), SC (chaîne d'approvisionnement), AI (fonctions IA), LOG (journalisation).
- Un finding renvoie à ses tests (TC), à ses menaces (TM), à sa mesure (M), et la mesure à ses retests (RT). La chaîne TM → TC → F → M → RT doit rester traçable.

## 4. Niveaux de confiance

| Statut | Définition |
|---|---|
| Confirmé | Reproduit en laboratoire, avec preuve (requête, réponse caviardée, commit testé) |
| Probable | Indices forts, non exploité |
| Théorique | Pattern de code ou de configuration, non démontré |

## 5. Quantifier, qualifier, hiérarchiser

Trois notions distinctes :

1. **Sévérité technique** : CVSS 4.0, vecteur complet obligatoire, avec métriques de menace et d'environnement quand elles sont connues.
2. **Niveau de confiance** : confirmé, probable, théorique.
3. **Priorité de correction** : décision qui combine sévérité, contexte et effort.

Facteurs de contexte :

- Sensibilité des données touchées (sensibles nLPD = aggravant fort).
- Exposition (internet sans authentification, utilisateurs authentifiés, admin seulement, labo seulement).
- Nombre de tenants et d'utilisateurs touchés.
- Exploitabilité réelle (preuve de concept, EPSS, présence dans CISA KEV pour une CVE).
- Effort et risque de la correction.

Échelle de priorité (proposition de départ, à ajuster par PA) :

| Priorité | Critère indicatif | Délai indicatif |
|---|---|---|
| P0 | Critique confirmée, exposée, données personnelles ou multi-tenant | Bloque la mise en prod, 24 à 72 h |
| P1 | Élevée, ou critique non exposée | Avant la prochaine release, 7 jours |
| P2 | Moyenne | 30 jours |
| P3 | Faible, durcissement | Backlog planifié |
| Info | Bonne pratique, observation | Sans délai |

Les délais sont des propositions, pas une norme.

## 6. Niveaux ASVS

- L1 : app simple, peu de données.
- L2 : défaut pour un SaaS avec données personnelles.
- L3 : données sensibles, haut enjeu (ex. app de suivi santé).

## 7. Style des sorties

- Réponse d'abord, détail ensuite. Une idée par phrase.
- Termes techniques définis une fois entre parenthèses.
- Étapes numérotées pour ce que PA doit faire.
- Jamais de tiret cadratin : tiret simple, virgule ou deux-points.
- Diagrammes en Mermaid.
- Tutoiement avec PA.
