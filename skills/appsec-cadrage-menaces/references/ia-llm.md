# Fonctions IA de l'app et pipeline de dev agentique

À lire en phase 1 si l'app appelle un LLM, embarque un RAG ou des agents, et en phase 2 pour la menace « agents IA de l'éditeur ». Ce fichier remplace le skill optionnel `appsec-ia-llm` de la carte initiale.

## 1. Référentiels

| Référentiel | État | Source |
|---|---|---|
| OWASP Top 10 for LLM Applications **2026** | Publié le 04.08.2026, vérifié le 23.11.2026 | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| OWASP Top 10 for Agentic Applications 2026 | Publié le 09.12.2025. Identifiants ASI01 à ASI10. **Noms des catégories à confirmer sur la publication officielle avant de les citer** (vus seulement dans des sources secondaires). | https://genai.owasp.org |

LLM Top 10:2026 : LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling.

## 2. Inventaire (phase 1)

| Élément | Question |
|---|---|
| Appels LLM | Côté navigateur ou côté serveur ? Quelle clé, où est-elle stockée ? |
| Entrées du prompt | Que vient de l'utilisateur, d'un document, d'une page web, d'un autre tenant ? |
| Sorties | Où sont affichées (Markdown, HTML), exécutées (SQL, code), ou transmises à un outil ? |
| Outils et agents | Quels outils l'agent peut appeler, avec quels droits (lecture, écriture, envoi de mail) ? |
| RAG | Les embeddings sont-ils cloisonnés par tenant ? Le filtre est-il côté serveur ? |
| Coûts | Y a-t-il un plafond par utilisateur et par tenant ? |
| Prompt système | Contient-il des secrets ou des règles d'autorisation ? |

## 3. Menaces types (phase 2)

| Menace | Catégorie LLM:2026 | Cas d'abus |
|---|---|---|
| Injection directe | LLM01 | Un utilisateur fait ignorer les consignes pour obtenir des données d'un autre tenant |
| Injection indirecte | LLM01 | Un document uploadé contient des instructions que l'agent exécute |
| Fuite inter-tenant via RAG | LLM02, LLM09 | La recherche vectorielle renvoie des extraits d'un autre tenant |
| Agentivité excessive | LLM03 | L'agent dispose d'un outil d'écriture ou d'envoi sans confirmation |
| Sortie non traitée | LLM10 | Le Markdown ou HTML généré exécute du script (lien avec V-FE-01) |
| Contexte caché exposé | LLM08 | Le prompt système ou un contexte interne est restitué à l'utilisateur |
| Consommation non bornée | LLM06 | Un utilisateur fait exploser la facture d'API (lien avec V-API-02) |

Règle de cotation : le LLM n'est jamais une frontière de sécurité. Toute autorisation doit être appliquée **hors du modèle** (RLS, contrôle serveur) ; une menace qui repose sur « le modèle refusera » démarre à vraisemblance élevée.

## 4. Pipeline de dev agentique (menace n° 5 du modèle d'attaquant)

À examiner pour toutes les apps de PA, puisqu'elles sont construites avec Claude Code :

- MCP Supabase ou accès SQL pointé sur la prod (V-AI-01).
- Fichiers d'instructions et contenus tiers lus par l'agent : injection de prompt possible (V-AI-02).
- Migrations générées qui désactivent RLS ou élargissent des droits pour faire passer un test (V-AI-03).
- Tests générés qui ne couvrent que le chemin nominal, sans test négatif d'autorisation (V-AI-04).
- Serveurs MCP et extensions non vérifiés (V-SC-04).

Ces points alimentent aussi les garde-fous de la phase 10 (`appsec-mitigation-retest`, puis `architecte-harnais`).
