# Phase 7 : analyse et cotation → `security/07-findings/F-xxx.md`

## Sommaire
1. Du résultat de test au finding
2. Coter avec CVSS 4.0
3. Repères pour les apps de PA
4. De la sévérité à la priorité
5. Regrouper ou séparer
6. Contrôles avant de rendre

## 1. Du résultat de test au finding

| Source | Devient | Statut |
|---|---|---|
| Échec d'un cas de test en phase 6, avec preuve | Finding | Confirmé |
| Signal statique confirmé en phase 5 (secret dans l'historique, table exposée sans RLS, bucket public) | Finding | Confirmé |
| Signal statique dont l'exploitation dépend d'une hypothèse non vérifiée | Finding | Probable |
| Motif de code sans démonstration | Finding seulement si le risque le justifie | Théorique |
| Écart fonctionnel (action légitime refusée) | Pas un finding de sécurité : note pour PA | |
| Non concluant, bloqué | Pas de finding : à rejouer | |

Chaque finding a : une **preuve**, une **cause racine**, une **mesure** M-xxx (même numéro que le finding par défaut : F-007 → M-007) et au moins un **retest** RT-xxx prévu (rédigé ensuite par `appsec-mitigation-retest`).

Créer la fiche : `python3 scripts/finding_tool.py nouveau security/07-findings --titre "..."`, puis la remplir au format partagé (`references/partage/formats.md`, section 2) **à l'identique**.

## 2. Coter avec CVSS 4.0

1. Choisir les métriques de base à partir de **ce qui a été démontré**, pas du pire imaginable. L'aide-mémoire : `python3 scripts/cvss_calc.py --metriques`.
2. Ajouter la métrique de menace `E` quand on la connaît (PoC dans le labo = au moins P).
3. Ajouter l'environnement quand il est connu : `CR:H` pour des données sensibles nLPD (santé), `IR`/`AR` selon l'enjeu.
4. Calculer : `python3 scripts/cvss_calc.py "<vecteur>"`. Recopier dans la fiche **le vecteur complet et le score calculés**, avec la nomenclature (CVSS-B, BT, BE, BTE).
5. Justifier en une ligne chaque métrique discutable dans la section Impact (« PR:L : un compte de n'importe quel tenant suffit »).

Le moteur est la bibliothèque `cvss` 3.6 : table de référence identique à celle de FIRST, scores conformes aux exemples officiels (vérifié le 23.11.2026). Ne jamais calculer un score de tête.

## 3. Repères pour les apps de PA

Points de départ, à adapter au cas démontré :

| Situation démontrée | Base indicative | Remarques |
|---|---|---|
| Lecture inter-tenant par API avec un compte de n'importe quel tenant | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | VC:H si les données de l'autre tenant sont lisibles en masse |
| Même lecture sans compte (clé publishable seule) | PR:N | |
| Écriture ou suppression inter-tenant | VI:H, et VA selon la suppression | |
| Auto-promotion admin ou ajout dans un autre tenant | VC:H/VI:H selon les droits obtenus | Souvent la plus grave d'une mission |
| Clé secrète dans le bundle ou l'historique | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H | Si la clé est encore valide ; sinon finding de processus |
| XSS stockée | UI:P ou UI:A, impact sur le système suivant (SC/SI) | |
| En-têtes manquants, durcissement | Souvent Info ou P3 | Pas de CVSS gonflé |

Données de santé ou autres données sensibles nLPD : ajouter `CR:H` (environnement), et le mentionner dans l'Impact.

## 4. De la sévérité à la priorité

La priorité n'est pas le score. Elle combine (`references/partage/conventions.md`, section 5) :

- la sévérité CVSS ;
- la sensibilité des données (sensible nLPD = aggravant fort) ;
- l'exposition réelle (internet sans compte, utilisateurs authentifiés, admin seulement, labo seulement) ;
- le nombre de tenants touchés ;
- l'exploitabilité réelle (PoC, EPSS, KEV pour une CVE) ;
- l'effort et le risque de la correction.

Échelle de départ : P0 (bloque la mise en prod, 24 à 72 h), P1 (avant la prochaine release, 7 jours), P2 (30 jours), P3 (backlog), Info. Les délais sont des propositions que PA ajuste. Dire en une phrase pourquoi la priorité diffère du score quand c'est le cas.

## 5. Regrouper ou séparer

- **Une cause racine = un finding**, même si plusieurs tests l'ont révélée (ex. une policy `using (true)` vue par REST et Realtime : un finding, deux tests).
- **Deux causes = deux findings**, même sur la même table (policy trop large et vue sans `security_invoker`).
- Une chaîne d'exploitation (vue → id → RPC) : un finding par maillon, et la chaîne décrite dans le rapport technique.

## 6. Contrôles avant de rendre

```bash
python3 scripts/finding_tool.py valider security/07-findings
python3 scripts/finding_tool.py tableau security/07-findings --sortie security/07-findings/index.md
```

Le validateur recalcule chaque CVSS, vérifie les champs, les sections, les identifiants ASVS, le renvoi M-xxx et l'absence de secret en clair. Vérifier les CWE avec `scripts/partage/ref_lookup.py cwe <n>` (et refuser un CWE déprécié).
