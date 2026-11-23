# Matrice d'autorisation : résultats (labo, 2026-11-23)

**53 échecs de sécurité**, 6 écarts fonctionnels, 59 contrôles conformes, 0 non exécutés, 0 non concluants.

Légende : ÉCHEC = accès qui aurait dû être refusé (faille). écart = refus d'une action attendue (fonctionnel, à vérifier). non concluant = cible déjà modifiée par un test précédent (remettre à zéro et rejouer). OK = conforme.

Cohérence de la cible : API d'authentification (/auth/v1/health → 200) OK; requête sans clé d'API refusée (401) OK; jeton forgé refusé (401) OK; filtre PostgREST respecté (description=eq.SECRET-TENANT-A-001 → 1 ligne) OK

| Preuve | Identité | Ressource | Action | Portée | Statut | Constat |
|---|---|---|---|---|---|---|
| P-002 | a-admin | accidents | lire | autre | ÉCHEC | marqueurs de B visibles : SECRET-TENANT-B-001, SECRET-TENANT-B-002 |
| P-006 | a-lecteur | accidents | lire | autre | ÉCHEC | marqueurs de B visibles : SECRET-TENANT-B-001, SECRET-TENANT-B-002 |
| P-004 | a-membre | accidents | lire | autre | ÉCHEC | marqueurs de B visibles : SECRET-TENANT-B-001, SECRET-TENANT-B-002 |
| P-001 | anon | accidents | lire | autre | ÉCHEC | marqueurs de A visibles : SECRET-TENANT-A-001, SECRET-TENANT-A-002 |
| P-008 | b-admin | accidents | lire | autre | ÉCHEC | marqueurs de A visibles : SECRET-TENANT-A-001, SECRET-TENANT-A-002 |
| P-012 | b-lecteur | accidents | lire | autre | ÉCHEC | marqueurs de A visibles : SECRET-TENANT-A-001, SECRET-TENANT-A-002 |
| P-010 | b-membre | accidents | lire | autre | ÉCHEC | marqueurs de A visibles : SECRET-TENANT-A-001, SECRET-TENANT-A-002 |
| P-028 | a-admin | entreprises | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-032 | a-lecteur | entreprises | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-030 | a-membre | entreprises | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-027 | anon | entreprises | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-034 | b-admin | entreprises | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-038 | b-lecteur | entreprises | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-036 | b-membre | entreprises | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-015 | a-admin | membres | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-081 | a-admin | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-019 | a-lecteur | membres | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-085 | a-lecteur | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-086 | a-lecteur | membres | creer | propre | ÉCHEC | insertion acceptée (201) |
| P-017 | a-membre | membres | lire | autre | ÉCHEC | marqueurs de B visibles : lignes du tenant B |
| P-083 | a-membre | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-084 | a-membre | membres | creer | propre | ÉCHEC | insertion acceptée (201) |
| P-014 | anon | membres | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-080 | anon | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-021 | b-admin | membres | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-087 | b-admin | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-025 | b-lecteur | membres | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-091 | b-lecteur | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-092 | b-lecteur | membres | creer | propre | ÉCHEC | insertion acceptée (201) |
| P-023 | b-membre | membres | lire | autre | ÉCHEC | marqueurs de A visibles : lignes du tenant A |
| P-089 | b-membre | membres | creer | autre | ÉCHEC | insertion acceptée (201) |
| P-090 | b-membre | membres | creer | propre | ÉCHEC | insertion acceptée (201) |
| P-055 | a-admin | photos | lister | autre | ÉCHEC | fichiers de B listés : ['SECRET-TENANT-B-101'] |
| P-056 | a-admin | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-B-101 lisible par URL publique |
| P-059 | a-lecteur | photos | lister | autre | ÉCHEC | fichiers de B listés : ['SECRET-TENANT-B-101'] |
| P-060 | a-lecteur | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-B-101 lisible par URL publique |
| P-057 | a-membre | photos | lister | autre | ÉCHEC | fichiers de B listés : ['SECRET-TENANT-B-101'] |
| P-058 | a-membre | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-B-101 lisible par URL publique |
| P-053 | anon | photos | lister | autre | ÉCHEC | fichiers de A listés : ['SECRET-TENANT-A-101'] |
| P-054 | anon | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-A-101 lisible par URL publique |
| P-061 | b-admin | photos | lister | autre | ÉCHEC | fichiers de A listés : ['SECRET-TENANT-A-101'] |
| P-062 | b-admin | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-A-101 lisible par URL publique |
| P-065 | b-lecteur | photos | lister | autre | ÉCHEC | fichiers de A listés : ['SECRET-TENANT-A-101'] |
| P-066 | b-lecteur | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-A-101 lisible par URL publique |
| P-063 | b-membre | photos | lister | autre | ÉCHEC | fichiers de A listés : ['SECRET-TENANT-A-101'] |
| P-064 | b-membre | photos | lire | autre | ÉCHEC | fichier SECRET-TENANT-A-101 lisible par URL publique |
| P-041 | a-admin | stats | appeler | autre | ÉCHEC | réponse pour le tenant B (données d'un autre tenant ?) |
| P-045 | a-lecteur | stats | appeler | autre | ÉCHEC | réponse pour le tenant B (données d'un autre tenant ?) |
| P-043 | a-membre | stats | appeler | autre | ÉCHEC | réponse pour le tenant B (données d'un autre tenant ?) |
| P-040 | anon | stats | appeler | autre | ÉCHEC | réponse pour le tenant A (données d'un autre tenant ?) |
| P-047 | b-admin | stats | appeler | autre | ÉCHEC | réponse pour le tenant A (données d'un autre tenant ?) |
| P-051 | b-lecteur | stats | appeler | autre | ÉCHEC | réponse pour le tenant A (données d'un autre tenant ?) |
| P-049 | b-membre | stats | appeler | autre | ÉCHEC | réponse pour le tenant A (données d'un autre tenant ?) |
| P-069 | a-admin | accidents | creer | propre | écart | insertion refusée (403) |
| P-095 | a-admin | accidents | modifier | propre | écart | action refusée sur SECRET-TENANT-A-002 (200) |
| P-071 | a-membre | accidents | creer | propre | écart | insertion refusée (403) |
| P-075 | b-admin | accidents | creer | propre | écart | insertion refusée (403) |
| P-101 | b-admin | accidents | modifier | propre | écart | action refusée sur SECRET-TENANT-B-002 (200) |
| P-077 | b-membre | accidents | creer | propre | écart | insertion refusée (403) |
| P-003 | a-admin | accidents | lire | propre | OK | lecture permise (attendu) |
| P-068 | a-admin | accidents | creer | autre | OK | insertion refusée (403) |
| P-094 | a-admin | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-106 | a-admin | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-113 | a-admin | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-007 | a-lecteur | accidents | lire | propre | OK | lecture permise (attendu) |
| P-072 | a-lecteur | accidents | creer | autre | OK | insertion refusée (403) |
| P-073 | a-lecteur | accidents | creer | propre | OK | insertion refusée (403) |
| P-098 | a-lecteur | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-099 | a-lecteur | accidents | modifier | propre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-108 | a-lecteur | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-115 | a-lecteur | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-005 | a-membre | accidents | lire | propre | OK | lecture permise (attendu) |
| P-070 | a-membre | accidents | creer | autre | OK | insertion refusée (403) |
| P-096 | a-membre | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-097 | a-membre | accidents | modifier | propre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-107 | a-membre | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-114 | a-membre | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-067 | anon | accidents | creer | autre | OK | insertion refusée (403) |
| P-093 | anon | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-112 | anon | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-009 | b-admin | accidents | lire | propre | OK | lecture permise (attendu) |
| P-074 | b-admin | accidents | creer | autre | OK | insertion refusée (403) |
| P-100 | b-admin | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-109 | b-admin | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-116 | b-admin | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-013 | b-lecteur | accidents | lire | propre | OK | lecture permise (attendu) |
| P-078 | b-lecteur | accidents | creer | autre | OK | insertion refusée (403) |
| P-079 | b-lecteur | accidents | creer | propre | OK | insertion refusée (403) |
| P-104 | b-lecteur | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-105 | b-lecteur | accidents | modifier | propre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-111 | b-lecteur | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-118 | b-lecteur | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-011 | b-membre | accidents | lire | propre | OK | lecture permise (attendu) |
| P-076 | b-membre | accidents | creer | autre | OK | insertion refusée (403) |
| P-102 | b-membre | accidents | modifier | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-103 | b-membre | accidents | modifier | propre | OK | action refusée sur SECRET-TENANT-B-002 (200) |
| P-110 | b-membre | accidents | deplacer | propre→autre | OK | déplacement refusé (200) |
| P-117 | b-membre | accidents | supprimer | autre | OK | action refusée sur SECRET-TENANT-A-002 (200) |
| P-029 | a-admin | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-033 | a-lecteur | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-031 | a-membre | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-035 | b-admin | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-039 | b-lecteur | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-037 | b-membre | entreprises | lire | propre | OK | lecture permise (attendu) |
| P-016 | a-admin | membres | lire | propre | OK | lecture permise (attendu) |
| P-082 | a-admin | membres | creer | propre | OK | insertion acceptée (201) |
| P-020 | a-lecteur | membres | lire | propre | OK | lecture permise (attendu) |
| P-018 | a-membre | membres | lire | propre | OK | lecture permise (attendu) |
| P-022 | b-admin | membres | lire | propre | OK | lecture permise (attendu) |
| P-088 | b-admin | membres | creer | propre | OK | insertion acceptée (201) |
| P-026 | b-lecteur | membres | lire | propre | OK | lecture permise (attendu) |
| P-024 | b-membre | membres | lire | propre | OK | lecture permise (attendu) |
| P-042 | a-admin | stats | appeler | propre | OK | réponse (attendu) |
| P-046 | a-lecteur | stats | appeler | propre | OK | réponse (attendu) |
| P-044 | a-membre | stats | appeler | propre | OK | réponse (attendu) |
| P-048 | b-admin | stats | appeler | propre | OK | réponse (attendu) |
| P-052 | b-lecteur | stats | appeler | propre | OK | réponse (attendu) |
| P-050 | b-membre | stats | appeler | propre | OK | réponse (attendu) |

Requêtes et extraits de réponses (jetons caviardés) : `matrice-resultats.json`. Remettre le labo à zéro après ce test (écritures de test) : `security/labo/labo.sh reset`.
