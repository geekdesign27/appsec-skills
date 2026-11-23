# Phase 8 : rapports → `security/08-rapports/`

## Sommaire
1. Trois niveaux de lecture
2. Synthèse direction (gabarit)
3. Rapport technique (gabarit)
4. Annexes
5. Règles de rédaction
6. Rapport pour un client (porte G4)

## 1. Trois niveaux de lecture

| Fichier | Lecteur | Longueur |
|---|---|---|
| `08-rapports/synthese-direction.md` | PA, direction, client non technique | 1 à 2 pages |
| `08-rapports/rapport-technique.md` | Développeur, IA de dev, RSSI | Selon le nombre de findings |
| `08-rapports/annexes.md` | Vérification, audit | Renvois vers les fichiers bruts |

Le squelette se génère avec les chiffres réels : `python3 scripts/rapport_squelette.py <racine-app>`. Il remplit les indicateurs et le tableau des findings ; la prose reste à écrire.

## 2. Synthèse direction (gabarit)

```markdown
# <App> : synthèse sécurité (<date>)

**Verdict** : <une phrase : mise en prod oui / non / sous conditions>.

## Posture globale
<2 à 3 phrases, langage métier, sans jargon>

## Risques majeurs
1. <risque en langage métier : qui peut faire quoi, sur quelles données> (P0)
2. ...
(3 à 5 au plus)

## Décision attendue
<ce que la direction doit décider, et quand>

## Effort de correction
<estimation globale, avec l'incertitude>

## Indicateurs
| Findings P0 | P1 | P2 | P3 | Couverture ASVS | Cas de test réussis |
|---|---|---|---|---|---|
```

Analogie SST possible : la synthèse est l'équivalent du rapport d'audit remis à la direction, avec les non-conformités majeures et le plan d'action.

## 3. Rapport technique (gabarit)

```markdown
# <App> : rapport technique de sécurité (<date>, commit <sha>)

## 1. Périmètre et méthode
Périmètre, environnements testés (labo, staging après G3), niveau ASVS, référentiels et versions, outils et versions, dates.

## 2. Résumé des résultats
Indicateurs : findings par priorité et statut, couverture ASVS, taux de cas réussis, tendance si campagne précédente.

## 3. Tableau des findings
(trié par priorité, puis score)

## 4. Détail des findings
Un sous-chapitre par finding, repris de F-xxx.md (statut, CVSS, preuve caviardée, impact, cause racine, mesure).

## 5. Testé sans anomalie
Ce qui a résisté. Sans cette section, on ne peut pas juger la couverture.

## 6. Non testé et limites
Ce qui n'a pas été couvert et pourquoi ; écarts labo/prod ; hypothèses.

## 7. Suite
Pack de mitigation (appsec-mitigation-retest), retest, régression en CI.
```

## 4. Annexes

Plan de test exécuté (`03-plan.yaml`), résultats bruts (`05-statique/`, `06-dynamique/`), journal, versions des outils et des référentiels, preuves détaillées. Renvoyer vers les fichiers plutôt que les recopier.

## 5. Règles de rédaction

1. Réponse d'abord, détail ensuite. Une idée par phrase.
2. Terme technique défini une fois entre parenthèses (8 mots au plus).
3. Toujours dire ce qui a été **testé sans anomalie** et ce qui **n'a pas été testé**.
4. Statut explicite pour chaque finding : confirmé, probable ou théorique. Ne jamais présenter un probable comme confirmé.
5. Preuves caviardées. Aucune donnée réelle.
6. Aucun identifiant ASVS, WSTG, CWE ni article de loi de mémoire.
7. Diagrammes (chaîne d'exploitation, DFD) en Mermaid.
8. Pas de tiret cadratin.

## 6. Rapport pour un client (porte G4)

1. **Vérifier qui est le destinataire** avant d'écrire pour lui : propriétaire de l'app (il a signé les règles d'engagement) ou simple client d'une plateforme multi-tenant ? Un client de la plateforme ne reçoit jamais le détail des failles qui exposent les autres clients, surtout avant correction. En cas de doute, demander à PA et le noter au journal.
2. Produire d'abord les rapports internes ci-dessus.
3. Passer le style par le skill `ecriture`.
4. Mettre à la charte SecurTec avec `rapport-securtec` (ou `securtec-documents`) : ce skill-là produit le Word et le PDF.
5. **Porte G4** : ne rien envoyer à un tiers sans la validation explicite de PA, notée au journal. Vérifier qu'aucune preuve ne contient de secret ou de donnée réelle.
6. Si le rapport engage SecurTec (attestation, conclusions de conformité), faire relire par `juriste-suisse`.
7. Un rapport de tests internes en boîte grise n'est pas un pentest tiers indépendant : le dire si le client en a besoin pour un RSSI.
