# Résultats et preuves de la phase 6

## 1. Statut d'un cas de test

| Statut | Sens |
|---|---|
| Réussi | Le contrôle a résisté : résultat sécurisé observé (ex. aucune ligne de B) |
| Échec | La faille est démontrée : critère d'échec du cas atteint, avec preuve |
| Bloqué | Le test n'a pas pu tourner (prérequis absent, labo cassé) : dire pourquoi |
| Non exécuté | Volontairement non joué (hors périmètre, porte non franchie, temps) : dire pourquoi |
| Non concluant | Le test a tourné, mais sa cible avait été modifiée par un test précédent, ou la cible ne se comportait pas comme un Supabase de labo : remettre à zéro, réparer, rejouer |

Un **échec** donne un finding au statut **Confirmé** (reproduit, avec preuve). Un comportement suspect non démontré reste **Probable**.

## 2. Arborescence de `security/06-dynamique/`

```
06-dynamique/
  resultats.md              tableau TC → statut → preuve → menace → suite
  matrice.yaml              matrice d'autorisation (entrée)
  matrice-resultats.md/json sortie du script
  preuves/P-xxx.md          une preuve détaillée par échec important
  outils/                   sorties brutes (ZAP, Nuclei, Schemathesis), versions des outils
```

Format de `resultats.md` :

```markdown
# Tests dynamiques : résultats (<date>, commit <sha>, cible labo)

**En bref** : <n> échecs, <n> réussis, <n> bloqués, <n> non exécutés sur <n> cas du plan.

| TC | Titre | Statut | Preuve | Menaces | Suite |
|---|---|---|---|---|---|
| TC-AUTHZ-012 | a-member lit les audits de B | Échec | P-002 | TM-004 | Finding (appsec-rapports) |

## Testé sans anomalie
## Non exécuté ou bloqué (et pourquoi)
## Limites (labo vs prod)
```

## 3. Format d'une preuve

```markdown
# P-002 : lecture inter-tenant de la table audits

- Cas : TC-AUTHZ-012   Identité : a-member   Cible : labo 127.0.0.1   Commit : <sha>   Date : <horodatage>
- Requête : GET /rest/v1/audits?select=titre,tenant_id   (Authorization : Bearer eyJ…[jeton caviardé])
- Réponse : 200, 4 lignes dont 2 du tenant B ; extrait caviardé : [{"titre":"SECRET-TENANT-B-001", ...}]
- Critère d'échec atteint : présence de SECRET-TENANT-B-001
- Reproduction : `python3 scripts/matrice_autorisation.py executer security/06-dynamique/matrice.yaml` (ligne P-002)
```

Règles :

1. Jetons, clés et mots de passe toujours caviardés (le script le fait pour sa sortie).
2. Seules des données synthétiques marquées figurent dans une preuve. Une donnée réelle n'y entre jamais.
3. Une preuve doit être **rejouable** : commande, identité, commit.

## 4. Relais

- Échecs → `appsec-rapports` (cotation CVSS 4.0, fiche finding au format partagé, priorité).
- Écarts fonctionnels → PA (règle métier à confirmer), pas un finding de sécurité.
- Tests automatisables qui ont échoué → futurs tests de régression (`appsec-mitigation-retest`).
- Journal : une ligne par lot exécuté (date, commit, cible, résultat en une phrase).
