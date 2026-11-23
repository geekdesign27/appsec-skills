# Modélisation des menaces : suivi-sante

| ID | Flux | STRIDE | Attaquant | Menace | Catalogue | Vraisemblance | Impact | Cote |
|---|---|---|---|---|---|---|---|---|
| TM-001 | F2 navigateur → PostgREST | I | 1 Autre cabinet | Un soignant du cabinet A lit les mesures des patients du cabinet B | V-DB-02, V-DB-05 | Élevée | Élevé | Critique |
| TM-002 | F2 navigateur → PostgREST | I | 2 Patient | Un patient lit les mesures d'un autre patient via get_mesures(patient_id) | V-DB-08, V-AUTH-06 | Élevée | Élevé | Critique |
| TM-003 | F2 navigateur → PostgREST | E | 3 Patient ambitieux | Un patient passe soignant en modifiant profiles.role | V-DB-09 | Moyenne | Élevé | Élevé |
| TM-004 | F1 bundle → navigateur | I | 6 Externe anonyme | Clé secret présente dans le bundle ou l'historique git | V-SEC-01, V-SEC-03 | Moyenne | Élevé | Élevé |
| TM-005 | F4 navigateur → Edge resume-ia | I | 1 Autre cabinet | Injection de prompt pour obtenir le résumé d'un patient d'un autre cabinet | V-AI-02 | Moyenne | Élevé | Élevé |
| TM-006 | F5 navigateur → Storage | I | 2 Patient | Accès aux PDF d'ordonnances d'un autre patient par URL devinable | V-DB-10 | Moyenne | Élevé | Élevé |
| TM-007 | F3 navigateur → Auth | S | 6 Externe anonyme | Brute force du login sans limitation | V-API-02 | Moyenne | Moyen | Moyen |
| TM-008 | F4 navigateur → Edge resume-ia | D | 2 Patient | Appels répétés au LLM qui font exploser la facture | V-API-02 | Moyenne | Moyen | Moyen |
