# Contexte de PA et pont SST (profil AppSec, sections 1.4 et 2)

> Fichier partagé par toute la famille `appsec-*`. Source : `partage/` à la racine du dépôt `appsec-skills`.

## 1. Qui est PA

- Pierre-Alain Schütz (PA), SecurTec / GeekDesign, Fribourg. Spécialiste SST (santé et sécurité au travail).
- **Vibecodeur** : il construit ses apps avec Claude Code, sans formation classique de développeur.
- Stack principale : React + Vite + TypeScript + TailwindCSS + Supabase, déploiement Vercel. Aussi Odoo 19 (cloud), WeWeb, WordPress pour des clients.
- Apps typiques : SaaS métier SST multi-tenant (ex. AuditApp), outils web de méthode Suva, plateformes de conduite de crise, apps personnelles dont une app de suivi santé (**données sensibles au sens de la nLPD**).
- Harnais de dev : GeekDesignCoding (gdc), méthode GeekDesign_DevFlow. Les règles de sécurité doivent pouvoir y être injectées.
- Navigateur de test : **Dev Browser** (CLI `dev-browser`, page nommée « main ») quand il est disponible ; sinon Playwright.
- Lecteur avec TDAH : sorties courtes, une idée par phrase, réponse d'abord, étapes numérotées, pas de tiret cadratin.

## 2. Skills voisins

| Skill | Quand l'appeler |
|---|---|
| `dev-senior` | Reçoit le pack de mitigation, propose les diffs (porte G5) |
| `architecte-harnais` | Reçoit les garde-fous préventifs (AGENTS.md / CLAUDE.md, hooks, règles) |
| `rapport-securtec`, `securtec-documents` | Rapport client à la charte SecurTec (porte G4) |
| `ecriture` | Style d'un texte destiné à un tiers |
| `juriste-suisse` | Portée juridique des règles d'engagement d'un mandat client |
| `web-security-audit` | Question défensive ponctuelle, hors mission structurée |

## 3. Pont avec le métier SST

À utiliser pour vulgariser, sans forcer l'analogie.

| Sécurité applicative | Équivalent SST |
|---|---|
| Modélisation des menaces | Détermination des dangers |
| Cas de test | Point de contrôle d'audit |
| Finding (vulnérabilité constatée) | Non-conformité constatée |
| CVSS + contexte = priorité | Matrice gravité x probabilité |
| Défense en profondeur | Hiérarchie S-T-O-P |
| Supprimer la fonction risquée | S : substitution / suppression |
| RLS, validation serveur, CSP | T : mesure technique |
| Revue de code, processus de release | O : mesure organisationnelle |
| Former le dev / règles dans le harnais | P : mesure personnelle |
| Retest | Contrôle d'efficacité des mesures |
