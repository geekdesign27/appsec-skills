# Journal de mission : chantier-pro

| Date | Phase | Événement ou décision | Par |
|---|---|---|---|
| 2026-11-23 | 0 | Arborescence security/ initialisée (10 fichiers créés), ASVS L2 | appsec-chef-de-mission |
| 2026-11-18 | 0 | G1 franchie : « OK, c'est mon app, labo local uniquement » | PA |
| 2026-11-20 | 3 | G2 franchie : « go pour les lots 1 et 2 en labo local » | PA |
| 2026-11-21 | 4 | Labo monté, vérification verte | appsec-labo |
| 2026-11-23 | 6 | Lot 1 (labo 127.0.0.1:54321, migrations fac5894dfbec/acd8bce9b61a, pas de commit git) : 6 cas en échec (lecture accidents, Storage, RPC stats, escalade admin, modification membres/entreprises inter-tenant), écriture accidents inter-tenant refusée, Realtime/Edge/dépôt Storage bloqués. Labo à remettre à zéro (labo.sh reset, CLI absente ici). | appsec-tests-dynamiques |
