# Référentiels et outils (état vérifié le 23.11.2026)

> Fichier partagé par toute la famille `appsec-*`. Source : `partage/` à la racine du dépôt `appsec-skills`.
> Revérifier en début de mission (règle 4.2) et noter la date dans `security/journal.md`.

## 1. Référentiels

| Référentiel | Version | Usage | Source vérifiée |
|---|---|---|---|
| OWASP Top 10 | 2025 (RC en novembre 2025, version finale fin décembre 2025) | Catégories de risque, langage commun du rapport | https://github.com/OWASP/Top10 |
| OWASP ASVS | 5.0.0 (30.05.2025), aucun correctif 5.0.x | **Quoi vérifier**, par niveau L1/L2/L3 | https://github.com/OWASP/ASVS |
| OWASP WSTG | 4.2 stable. La v5 est en cours sur la branche principale, non publiée. | **Comment tester**, identifiants WSTG-xxx | https://github.com/OWASP/wstg (tag v4.2) |
| OWASP API Security Top 10 | 2023 | API REST/RPC, PostgREST, Edge Functions | https://github.com/OWASP/API-Security |
| OWASP Top 10 for LLM Applications | **2026** (publié le 04.08.2026) | Fonctions IA intégrées à l'app | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| OWASP Top 10 for Agentic Applications | 2026 (publié le 09.12.2025) | Agents dans l'app et pipeline de dev agentique | https://genai.owasp.org (identifiants ASI01 à ASI10) |
| OWASP Cheat Sheet Series | Courante | Mesures de correction | https://cheatsheetseries.owasp.org |
| CVSS | 4.0 (FIRST), en vigueur | Sévérité technique | https://www.first.org/cvss/v4.0/ |
| CWE (MITRE) | Courante | Classification de la faiblesse | https://cwe.mitre.org |
| EPSS / CISA KEV | Courantes. Version du modèle EPSS non confirmée (v5 annoncée par des sources secondaires). | Exploitabilité réelle des CVE | https://api.first.org/data/v1/epss ; https://github.com/cisagov/kev-data |
| PTES / NIST SP 800-115 | De référence | Structure de la démarche | |
| nLPD (CH) | En vigueur depuis le 01.09.2023 (RS 235.1) | Classification des données, obligations, violations | https://www.fedlex.admin.ch |

**Top 10:2025** : A01 Broken Access Control (inclut SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.

**LLM Top 10:2026** : LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling. (Source : README officiel GenAI-Security-Project/GenAI-LLM-Top10.)

**Règle d'usage** : le Top 10 n'est pas une checklist de conformité. L'ASVS dit quoi vérifier, le WSTG dit comment, le Top 10 sert à communiquer.

## 2. Obtenir un identifiant sans le citer de mémoire

Utiliser `scripts/partage/ref_lookup.py` :

```bash
python3 scripts/partage/ref_lookup.py asvs "row level"        # recherche par mot-clé (anglais)
python3 scripts/partage/ref_lookup.py asvs V8.2.2             # par identifiant
python3 scripts/partage/ref_lookup.py asvs --chapitre V8 --niveau 2   # exigences d'un chapitre jusqu'au niveau L2
python3 scripts/partage/ref_lookup.py wstg "insecure direct"  # WSTG v4.2
python3 scripts/partage/ref_lookup.py cwe 639                 # titre officiel MITRE
```

Formats de citation :

- ASVS : `v5.0.0-8.2.2` (forme recommandée par l'ASVS). Le CSV officiel écrit `V8.2.2`.
- WSTG : `WSTG-v42-ATHZ-04` dans un rapport, `WSTG-ATHZ-04` dans un cas de test.
- CWE : `CWE-639`.

Si le script ne peut pas joindre la source, écrire l'identifiant suivi de « (à vérifier) ».

## 3. Point Supabase daté

- Clés **publishable** (`sb_publishable_...`) et **secret** (`sb_secret_...`) remplacent `anon` et `service_role`. Selon la doc officielle, les anciennes clés sont dépréciées d'ici fin 2026 ; la suppression est annoncée « Late 2026 (TBC) », sans date ferme. Les nouveaux projets n'ont plus les anciennes clés depuis novembre 2025. Vérifier l'état réel à chaque mission.
- La clé publishable a les mêmes droits que `anon` : **elle est publique par nature, la sécurité repose entièrement sur RLS**.
- Le rôle `service_role` (clé secret) a l'attribut BYPASSRLS : il ignore toutes les policies. Sa présence côté client est une faille critique.
- Cas d'école : CVE-2025-48757 (RLS insuffisante dans des apps générées par Lovable, CVSS 3.1 de 9.3, CWE-863). Le fournisseur conteste ce CVE (« disputed »).

## 4. Outils du laboratoire (vérifiés le 23.11.2026)

| Outil | Version de référence | Point d'attention |
|---|---|---|
| Supabase CLI | 3.2.0 | v3 : tout est local par défaut, l'hébergé exige `--remote` et une confirmation. `[inbucket]` remplacé par `[local_smtp]` (Mailpit). Postgres ≥ 14. Ne jamais exporter `SUPABASE_YES` dans le labo. `supabase db advisors --type security` intègre les lints splinter. |
| pgTAP | 1.3.4 | Via `supabase test db` |
| ZAP | 2.17.1 | Image `ghcr.io/zaproxy/zaproxy:stable`. `owasp/zap2docker-*` est déprécié. |
| Nuclei | 3.11.1 | Les modèles `javascript:` maison doivent être signés (`nuclei -sign`), sinon ignorés. |
| Semgrep CE / Opengrep | 1.186.0 / 2.0.0 | Règles officielles Semgrep sous licence restrictive (usage interne). Opengrep : fork libre. Règles maison : utilisables avec les deux. |
| TruffleHog | 3.100.0 | Scanner de secrets principal |
| gitleaks / Betterleaks | 8.30.1 / à vérifier | gitleaks en maintenance ; Betterleaks reprend sa configuration |
| osv-scanner | 2.7.1 | Ligne v2 |
| Trivy | ≥ 0.76.2 | **Compromis en mars 2026** (CVE-2026-33634) : versions 0.69.4 à 0.69.6 et trivy-action ≤ 0.34.2 malveillantes. Épingler par digest. |
| Socket CLI | 1.16.0 | Paquets npm malveillants, typosquat, slopsquatting |
| zizmor | 1.33.1 | Analyse des workflows GitHub Actions |
| Schemathesis | 4.34.0 | CLI 4.x différente de la 3.x |
| ffuf | 2.3.0 | |
| sqlmap | 1.10.11 | **Labo uniquement** |
| Playwright | 1.65.1 | Ou Dev Browser (`dev-browser`, page « main ») si disponible |
| npm | 12.x | Scripts d'installation des dépendances désactivés par défaut |
| Burp Suite | 2026.4.x (à vérifier) | Sur le Mac de PA |

Toujours épingler les images et binaires par version (et digest pour les conteneurs), jamais `latest`.
