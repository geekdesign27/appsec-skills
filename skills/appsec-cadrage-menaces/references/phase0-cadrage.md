# Phase 0 : cadrage et autorisation → `security/00-cadrage.md`

Objectif : savoir **qui autorise quoi, où, et pour quel enjeu**, avant de toucher à quoi que ce soit. C'est l'équivalent du permis de travail sur un chantier : sans lui, personne n'entre dans la zone.

## 1. Identifier l'app

| Question | Pourquoi |
|---|---|
| Nom, dépôt, commit de référence | Les résultats se rattachent à un commit précis |
| Propriétaire (PA ou client) | Décide qui signe l'autorisation |
| Environnements : labo local, preview/staging, prod, avec URLs | Décide où chaque test peut tourner |
| Fournisseurs : Supabase (projet, région), Vercel (**plan**), autres API | Politiques de test à respecter |
| Utilisateurs réels déjà présents ? | Change l'urgence et la prudence en staging |

**Plan Vercel** : Hobby = pentest interdit sur l'app hébergée ; seuls le labo et l'observation passive restent possibles. Pro ou Enterprise = tests non volumétriques permis sur ses propres apps. Volumétrique = Enterprise avec préavis. Source et date dans `partage/regles.md`, section 5.

## 2. Classer les données (nLPD)

| Classe | Exemples dans les apps de PA | Conséquence |
|---|---|---|
| Publique | Contenu marketing, liste de communes | Peu de contraintes |
| Interne | Paramètres d'entreprise, plans d'action sans nom | Contrôle d'accès standard |
| Personnelle | Nom, e-mail, fonction, signature | nLPD : sécurité adéquate, minimisation |
| Sensible nLPD | Santé (accidents avec lésions, aptitude, suivi santé), données biométriques, poursuites ou sanctions | Aggravant fort en cotation, ASVS L3 à envisager, annonce de violation possible |

Pour la qualification exacte d'une donnée sensible, s'appuyer sur le texte de la nLPD dans Fedlex (ne pas citer l'article de mémoire). En cas de doute, classer au niveau supérieur et le noter.

**Minimisation** : avant de tester, se demander si la donnée la plus sensible est vraiment nécessaire. Ne pas la stocker reste la meilleure mesure (niveau S de la hiérarchie S-T-O-P). Le signaler à PA quand c'est pertinent, sans en faire un préalable.

## 3. Choisir le niveau ASVS

| Niveau | Quand | Ordre de grandeur (exigences cumulées ASVS 5.0.0) |
|---|---|---|
| L1 | App simple, peu ou pas de données personnelles | 70 |
| L2 | **Défaut** : SaaS avec données personnelles, multi-tenant | 253 |
| L3 | Données sensibles nLPD, fort enjeu | 345 |

Les ordres de grandeur sont calculés sur le CSV officiel (`scripts/plan_tool.py asvs --niveau N --compter`). Toutes les exigences ne s'appliquent pas : WebRTC (V17) ou OAuth (V10) sortent souvent du périmètre. La phase 3 retient les applicables.

## 4. Règles d'engagement

Remplir chaque rubrique de `00-cadrage.md` :

1. **Périmètre inclus** : dépôt, labo, environnements hébergés autorisés.
2. **Périmètre exclu** : infrastructure des fournisseurs, comptes réels, services tiers, et tout ce que PA exclut.
3. **Environnements et niveau de risque autorisé** : tableau environnement x (faible, moyen, destructif). Destructif = labo uniquement.
4. **Fenêtres de test** pour les environnements hébergés.
5. **Tests interdits** : DoS, ingénierie sociale, tests sur données réelles, attaques de la plateforme.
6. **Contacts et arrêt d'urgence** : qui arrête, par quel canal, sur quels critères, comment nettoyer.
7. **Conduite si une donnée réelle est atteinte** : arrêt immédiat, pas de copie, consignation au journal, information de PA.
8. **Autorisation** : référence du message ou du document, date.

| Cas | Forme d'autorisation |
|---|---|
| App de PA | Accord explicite de PA, cité mot pour mot dans le journal |
| App d'un client | Règles d'engagement signées par une personne habilitée du client. Faire relire par `juriste-suisse`. Un accord oral ne suffit pas. |
| Multi-tenant, tenant d'un client | L'accord du client est requis pour toucher à son tenant, même avec des données synthétiques |

## 5. Porte G1

Présenter à PA, en peu de lignes : périmètre, environnements, niveau ASVS proposé et sa justification, ce qui n'est pas couvert. Attendre sa validation. Noter la décision au journal, mot pour mot.
