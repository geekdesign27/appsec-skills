# Outillage du labo et autres plateformes

## 1. Conteneur d'outils

Le fichier `assets/docker-compose.outils.yml` décrit les outils de test. Principes :

- **Épinglés par digest** (empreinte exacte de l'image), jamais `latest` en usage réel. La compromission de Trivy en mars 2026 (images 0.69.4 à 0.69.6) montre pourquoi. Lancer `assets/epingler_images.sh` une fois : il télécharge chaque image, lit son digest et réécrit le fichier.
- **Réseau** : `network_mode: host` pour atteindre la stack locale (127.0.0.1:54321). Les outils ne reçoivent aucun secret réel ; le dossier `security/` est monté pour écrire les résultats.
- **sqlmap et ffuf** : installés localement (pas d'image officielle vérifiée), labo uniquement, à ne pointer que vers 127.0.0.1.

| Outil | Phase | Usage dans le labo |
|---|---|---|
| ZAP | 6 | Scan de base de l'app Vite locale |
| Nuclei | 6 | Modèles ciblés. Modèles `javascript:` maison à signer (`nuclei -sign`) |
| Semgrep CE ou Opengrep | 5 | SAST et règles maison vibecoding |
| TruffleHog | 5 | Secrets dans tout l'historique git |
| osv-scanner | 5 | Dépendances vulnérables |
| Trivy (≥ 0.76.2) | 5 | Images et configuration |
| Socket CLI | 5 | Paquets npm malveillants ou hallucinés |
| zizmor | 5 | Workflows GitHub Actions |
| Schemathesis | 6 | Fuzzing par schéma OpenAPI de PostgREST |
| ffuf (installé localement) | 6 | Découverte de chemins, labo uniquement |
| sqlmap (pip, installé localement) | 6 | Injection SQL dans les RPC, **labo uniquement** |

Hors conteneur :

- **Dev Browser** (`dev-browser`, page « main ») si disponible, sinon **Playwright** : parcours authentifiés et tests d'autorisation scriptés avec les identités du labo.
- **pgTAP** via `supabase test db` : tests unitaires des policies, réutilisables en CI.
- **Burp Suite** sur le Mac de PA : tests manuels en proxy.

## 2. Autres plateformes

| Plateforme | Labo proposé | Identités | Points d'attention |
|---|---|---|---|
| Odoo 19 | Conteneurs `odoo` + `postgres` avec les modules custom montés, base de démo | 2 sociétés (multi-company) x rôles (utilisateur interne, manager, portail) + public | `ir.rule` multi-société, contrôleurs `auth='public'`, `sudo()`. Odoo Online (cloud) ne se reproduit pas à l'identique : signaler la limite. |
| WordPress | Conteneurs `wordpress` + `mariadb` avec les mêmes versions de plugins et thème | admin, éditeur, auteur, abonné + anonyme | WPScan en labo, `xmlrpc.php`, énumération d'utilisateurs |
| WeWeb | L'éditeur et l'hébergement WeWeb ne s'auto-hébergent pas : le labo porte sur le **backend** (Supabase ou Xano) et sur une preview WeWeb pointée vers ce backend de labo | Comme Supabase | L'autorisation doit être dans le backend. Les workflows front sont visibles par l'utilisateur. Politique de test de WeWeb à vérifier avant tout test sur leur hébergement. |
| Convex | Déploiement de développement local de Convex (à vérifier dans la doc Convex au moment de la mission) | Identités via le fournisseur d'auth configuré en mode test | Contrôle d'identité dans chaque query et mutation, fonctions `internal*` |

Pour toutes : mêmes principes (isolé, reproductible, réaliste, synthétique), deux tenants au moins, des marqueurs `SECRET-TENANT-X-nnn`, une commande pour monter et une pour remettre à zéro.
