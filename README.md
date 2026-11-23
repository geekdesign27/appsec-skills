# appsec-skills

Famille de skills Claude de sécurité applicative pour les apps web vibecodées de PA (SecurTec / GeekDesign).
Cahier des charges : profil « ingénieur sécurité applicative pour apps web vibecodées » v1.0 du 23.11.2026.

## Contenu

| Dossier | Rôle |
|---|---|
| `skills/<nom>/` | Un skill installable (SKILL.md, references/, scripts/, evals/) |
| `partage/` | **Source unique** des références et scripts communs, copiés dans chaque skill |
| `outils/sync_partage.py` | Copie `partage/` dans chaque skill et vérifie que les copies sont identiques |
| `workspaces/` | Résultats des évaluations (benchmark, visualiseur HTML) |

## Skills

| Skill | Phases | Déclencheurs |
|---|---|---|
| `appsec-chef-de-mission` | Toutes | `/appsec`, « Loïc », « audite la sécurité de mon app » |
| `appsec-cadrage-menaces` | 0 à 3 | `/menaces`, `/cadrage`, `/plan-test`, « fais le STRIDE », « quels tests faire » |
| `appsec-labo` | 4 | `/labo`, « monte le labo », « remets le labo à zéro », « comptes de test par rôle » |

(Les autres skills de la famille seront ajoutés au fil de leur création.)

## Installer

1. Claude Code : copier ou lier `skills/<nom>` dans `~/.claude/skills/`.
2. claude.ai : téléverser le fichier `dist/<nom>.skill`.

## Modifier une référence partagée

1. Modifier le fichier dans `partage/`.
2. Lancer `python3 outils/sync_partage.py`.
3. Vérifier que toutes les lignes affichent `OK`.
