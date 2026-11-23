# STRIDE détaillé pour les SaaS vibecodés

Repris et nettoyé du skill `pentest-saas-vibecoding` (persona Mathis Vernier), que cette famille remplace.
Les identifiants CWE ont été vérifiés sur cwe.mitre.org le 23.11.2026. Les références ASVS 4 de l'ancien fichier ont été retirées : en ASVS 5.0 la numérotation des chapitres a changé. Pour une exigence ASVS, utiliser `scripts/partage/ref_lookup.py`.

Colonne « Env. » : **passif** (observation, lecture du dépôt), **labo** (stack locale), **staging** (hébergé, non destructif, après G3). Rappel : tout ce qui est destructif reste en labo.

**Fil rouge multi-tenant** : pour chaque sous-vecteur, se demander s'il franchit la frontière `tenant_id` entre deux entreprises clientes. C'est la priorité n° 1.

## Sommaire
S · T · R · I · D · E

---

## S : Spoofing (usurpation), viole l'authentification

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| JWT volé ou rejoué | Rejouer un JWT après déconnexion ou au-delà de sa durée | labo | Session valide après logout ou expiration |
| Énumération de comptes | Comparer messages et temps de réponse login et reset selon que l'e-mail existe | labo | Message ou timing qui révèle l'existence d'un compte |
| `anon` traité comme `authenticated` | Appeler l'API avec la seule clé publishable, sans session | labo, puis staging en lecture | Des données reviennent sans authentification |
| Redirection OAuth ou magic link trop large | Lire la liste des URLs autorisées, chercher un joker | passif | Redirection acceptée vers un domaine non prévu |
| MFA absent pour les rôles sensibles | Se connecter en admin sans second facteur | labo | Privilèges élevés sans MFA |

Remédiation : sessions courtes et révocation à la déconnexion et au départ, messages d'erreur uniformes, URLs de redirection en liste stricte, MFA pour les rôles élevés.
CWE : 287 Improper Authentication, 384 Session Fixation, 307 Improper Restriction of Excessive Authentication Attempts.

## T : Tampering (altération), viole l'intégrité

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| UPDATE sans `WITH CHECK` | Écrire une ligne avec le `tenant_id` d'un autre | labo | L'écriture passe |
| Mass assignment | Envoyer des champs non prévus (`role`, `tenant_id`, `validated`) | labo | Les champs interdits sont pris en compte |
| Paramètre modifié côté client | Modifier la requête avant envoi | labo | Le serveur accepte ce que l'interface interdisait |
| Modification après validation | Modifier un rapport ou une déclaration clos | labo | Le verrou d'état n'est pas appliqué côté serveur |
| `tenant_id` forcé à l'insertion | Créer une ressource sous le tenant d'un autre | labo | La ressource est créée chez l'autre |

Remédiation : `WITH CHECK` sur toutes les policies d'écriture, colonnes sensibles protégées (jamais `tenant_id` ni `role` venant du client), tenant dérivé de `auth.uid()`, transitions d'état contrôlées en base.
CWE : 915 Improperly Controlled Modification of Dynamically-Determined Object Attributes, 639 Authorization Bypass Through User-Controlled Key, 471 Modification of Assumed-Immutable Data.

## R : Repudiation (répudiation), viole la non-répudiation

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| Suppression non tracée | Supprimer un enregistrement, chercher la trace | labo | Aucune trace de qui a supprimé quoi |
| Lecture sensible non journalisée | Lire un dossier de santé, vérifier le journal | labo | Pas de trace des accès aux données sensibles |
| Journal falsifiable | Vérifier qui peut écrire ou purger la table d'audit | passif | Un rôle applicatif peut modifier le journal |
| Horodatage côté client | Vérifier l'origine des dates | passif | La date vient du client |

Remédiation : journal en ajout seul hors de portée des rôles applicatifs, journalisation des lectures sensibles, horodatage serveur.
Note SST : après un accident et en cas de litige, l'absence de traçabilité des modifications d'un dossier est un défaut en soi.
CWE : 778 Insufficient Logging, 285 Improper Authorization.

## I : Information disclosure (divulgation), viole la confidentialité

La lettre qui tue un SaaS SST. Elle se décline à plusieurs profondeurs.

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| **Isolation inter-tenant** | Tenants synthétiques A et B : A tente de lire une ligne de B | labo, puis staging en lecture | A voit une ligne de B |
| RLS absente | Advisors Supabase, inventaire des tables | passif | Table de données personnelles sans RLS |
| Vue sans `security_invoker` | Lister les vues exposées | passif | Une vue contourne la RLS de l'appelant |
| Clé secret exposée | Bundle `dist/`, historique git | passif | Clé secret ou `service_role` accessible |
| Bucket public ou listable | Policies Storage | passif, labo | Fichiers listables ou accessibles sans droit |
| URL signée trop longue | Générer une URL, mesurer sa durée | labo | Lien partageable longtemps |
| RPC, GraphQL, Realtime | Inventaire des fonctions, canaux | passif, labo | Fonction ou canal sensible appelable |
| Liens de partage et exports | Exports PDF, portails, liens publics | labo | Un lien donne accès à un dossier |
| Colonnes en excès | Colonnes réellement renvoyées par l'API | labo | Colonnes sensibles inutiles renvoyées |
| Erreurs verbeuses | Provoquer une erreur | labo | Trace ou structure de base exposée |

Remédiation : RLS filtrant sur l'appartenance au tenant et `auth.uid()`, `security_invoker` sur les vues, clé secret strictement serveur, buckets privés, URLs signées courtes, exports authentifiés, sélection explicite des colonnes, erreurs génériques.
CWE : 284 Improper Access Control, 639 Authorization Bypass Through User-Controlled Key, 200 Exposure of Sensitive Information to an Unauthorized Actor, 209 Generation of Error Message Containing Sensitive Information.

## D : Denial of service, viole la disponibilité

**Tout test actif de DoS se fait en labo.** Supabase l'interdit sur sa plateforme et Vercel réserve le volumétrique à Enterprise avec préavis.

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| Requête non bornée | Requête sans limite sur une grosse table | labo | Temps et ressources explosent |
| Pas de limitation de débit | Répéter un endpoint coûteux (reset, recherche, LLM) | labo | Aucun plafond |
| Upload sans limite | Fichiers volumineux en masse | labo | Pas de limite de taille ou de nombre |
| Épuisement de quota ou de budget | Estimer le coût d'un appel LLM ou d'une requête | passif | Un utilisateur peut faire exploser la facture |
| Récursion de policy | Policy qui interroge une table elle-même protégée | passif | Boucle possible |

Remédiation : pagination obligatoire, limitation de débit, limites d'upload, index, policies non récursives, plafond de coût pour les fonctions IA.
CWE : 770 Allocation of Resources Without Limits or Throttling, 400 Uncontrolled Resource Consumption.

## E : Elevation of privilege, viole l'autorisation

| Sous-vecteur | Méthode | Env. | Signal de faille |
|---|---|---|---|
| Auto-promotion de rôle | `UPDATE` de son propre rôle via l'API | labo | L'update réussit |
| **Inscription ouverte** | Vérifier si n'importe qui peut créer un compte | passif | Toute policy `TO authenticated` devient ouverte à Internet |
| Rôle choisi à l'inscription | S'inscrire en fixant un rôle élevé | labo | Le rôle demandé est accepté |
| `SECURITY DEFINER` mal écrite | Appeler la fonction en utilisateur simple | labo | La RPC admin filtre mal l'appelant |
| `search_path` non fixé | Lire la définition des fonctions definer | passif | Détournement de schéma possible |
| Fonction admin appelable (BFLA) | Appeler une fonction réservée admin | labo | Un utilisateur simple l'exécute |
| **Franchissement de tenant** | Un admin du tenant A agit sur le tenant B | labo | L'action traverse la frontière |

Remédiation : `role` et `tenant_id` non modifiables par le client, rôle forcé à l'inscription, inscription fermée ou cloisonnée, fonctions definer avec contrôle de l'appelant et `search_path` fixé, autorisation vérifiée dans chaque fonction.
CWE : 269 Improper Privilege Management, 266 Incorrect Privilege Assignment, 862 Missing Authorization, 863 Incorrect Authorization.
