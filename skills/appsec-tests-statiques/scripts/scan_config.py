#!/usr/bin/env python3
"""Contrôles statiques de configuration, de secrets « visibles » et du bundle construit (phase 5).

Usage :
  scan_config.py <racine-app> [--dist dist] [--sortie security/05-statique/config.md]

Contrôle, sans aucune requête réseau :
  1. Fichiers .env suivis par git, et secrets visibles dans les fichiers suivis (motifs ciblés Supabase/Vercel/LLM).
  2. Variables à préfixe public (VITE_, NEXT_PUBLIC_) dont le nom évoque un secret.
  3. Bundle construit (dist/) : clé secrète, JWT de rôle service_role (payload décodé), source maps, URLs de projet.
  4. supabase/config.toml : inscription ouverte, confirmation e-mail, redirections à joker, MFA, verify_jwt = false.
  5. Edge Functions : CORS « * », usage de la clé secrète, absence de lecture du JWT appelant.
  6. vercel.json : en-têtes de sécurité (CSP, HSTS, X-Content-Type-Options, frame-ancestors), previews.
  7. React : dangerouslySetInnerHTML, rendu Markdown/HTML brut.
Chaque résultat est un signal relié au catalogue partagé, à qualifier ensuite (statut, preuve) par appsec-rapports.
Les valeurs de secrets trouvées sont CAVIARDÉES dans la sortie (4 premiers caractères).
Le scan d'historique git complet reste le travail de TruffleHog (voir references/outils-phase5.md).
"""
import argparse
import base64
import glob
import json
import os
import re
import subprocess
import tomllib

MOTIFS_SECRETS = {
    "clé secrète Supabase": r"sb_secret_[A-Za-z0-9_\-]{16,}",
    "JWT (à décoder)": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "clé Anthropic": r"sk-ant-[A-Za-z0-9_\-]{20,}",
    "clé OpenAI": r"sk-(?:proj-)?[A-Za-z0-9]{20,}",
    "jeton GitHub": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "chaîne Postgres avec mot de passe": r"postgres(?:ql)?://[^:\s/]+:[^@\s]{4,}@[^\s'\"]+",
    "clé Stripe secrète": r"sk_live_[A-Za-z0-9]{16,}",
}
NOMS_SENSIBLES = re.compile(r"(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|TOKEN|API_KEY|_KEY_SECRET|DB_URL|DATABASE_URL)", re.I)
TEXTE = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".toml", ".yml", ".yaml", ".env", ".sql", ".md", ".html", ".vue")


def caviarder(v):
    return v[:4] + "…[caviardé]"


def decode_jwt(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def fichiers_suivis(racine):
    try:
        out = subprocess.run(["git", "-C", racine, "ls-files"], capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            return [l for l in out.stdout.splitlines() if l]
    except Exception:
        pass
    res = []
    for d, sub, fs in os.walk(racine):
        sub[:] = [s for s in sub if s not in ("node_modules", ".git", "dist", "security")]
        res += [os.path.relpath(os.path.join(d, f), racine) for f in fs]
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("racine")
    ap.add_argument("--dist", default="dist")
    ap.add_argument("--sortie")
    a = ap.parse_args()
    R = os.path.abspath(a.racine)
    S = []

    def add(cid, objet, constat, ind):
        S.append((cid, objet, constat, ind))

    suivis = fichiers_suivis(R)
    # 1. .env suivis et secrets visibles
    for f in suivis:
        base = os.path.basename(f)
        if re.match(r"^\.env(\..+)?$", base) and not base.endswith((".example", ".sample", ".lab")):
            add("V-SEC-03", f, "fichier .env suivi par git", "élevée")
        if not f.endswith(TEXTE) and not base.startswith(".env"):
            continue
        if f.startswith(("security/", "node_modules/")) or "/evals/" in f:
            continue
        try:
            txt = open(os.path.join(R, f), encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for nomm, motif in MOTIFS_SECRETS.items():
            for m in re.finditer(motif, txt):
                v = m.group(0)
                if nomm.startswith("JWT"):
                    role = decode_jwt(v).get("role")
                    if role != "service_role":
                        continue
                    nomm2 = "JWT de rôle service_role"
                else:
                    nomm2 = nomm
                if "127.0.0.1" in v or "localhost" in v or "postgres:postgres@" in v:
                    continue
                add("V-SEC-03", f"{f}:{txt[:m.start()].count(chr(10)) + 1}", f"{nomm2} visible dans un fichier suivi ({caviarder(v)})", "élevée")
        # 2. variables publiques au nom sensible
        for m in re.finditer(r"\b(VITE_|NEXT_PUBLIC_)([A-Z0-9_]+)", txt):
            if NOMS_SENSIBLES.search(m.group(2)) and "PUBLISHABLE" not in m.group(2) and "ANON" not in m.group(2):
                add("V-SEC-02", f, f"variable publique au nom de secret : {m.group(1)}{m.group(2)}", "élevée")
    # 3. bundle
    dist = os.path.join(R, a.dist)
    if os.path.isdir(dist):
        maps = glob.glob(os.path.join(dist, "**", "*.map"), recursive=True)
        if maps:
            add("V-SEC-05", a.dist, f"{len(maps)} source maps présentes dans le bundle construit", "moyenne")
        for js in glob.glob(os.path.join(dist, "**", "*.js"), recursive=True):
            txt = open(js, encoding="utf-8", errors="ignore").read()
            rel = os.path.relpath(js, R)
            for m in re.finditer(MOTIFS_SECRETS["clé secrète Supabase"], txt):
                add("V-SEC-01", rel, f"clé secrète Supabase dans le bundle ({caviarder(m.group(0))})", "élevée")
            for m in re.finditer(MOTIFS_SECRETS["JWT (à décoder)"], txt):
                if decode_jwt(m.group(0)).get("role") == "service_role":
                    add("V-SEC-01", rel, f"JWT service_role dans le bundle ({caviarder(m.group(0))})", "élevée")
    else:
        add("info", a.dist, "pas de bundle construit : lancer « npm run build » puis relancer pour contrôler dist/", "info")
    # 4. config.toml
    ct = os.path.join(R, "supabase", "config.toml")
    if os.path.exists(ct):
        try:
            c = tomllib.load(open(ct, "rb"))
        except Exception as e:
            c = {}
            add("info", "supabase/config.toml", f"illisible : {e}", "info")
        auth = c.get("auth", {})
        if auth.get("enable_signup", True):
            add("V-AUTH-02", "supabase/config.toml [auth]", "inscription ouverte (enable_signup) : à confirmer comme voulu", "moyenne")
        if auth.get("email", {}).get("enable_confirmations") is False:
            add("V-AUTH-03", "supabase/config.toml [auth.email]", "confirmation d'e-mail désactivée", "moyenne")
        for u in auth.get("additional_redirect_urls", []) or []:
            if "*" in u:
                add("V-AUTH-04", "supabase/config.toml [auth]", f"URL de redirection à joker : {u}", "élevée")
        if not (auth.get("mfa", {}).get("totp", {}) or {}).get("enroll_enabled"):
            add("V-AUTH-03", "supabase/config.toml [auth.mfa]", "MFA TOTP non activé (à exiger pour les rôles admin)", "info")
        for fn, d in (c.get("functions") or {}).items():
            if isinstance(d, dict) and d.get("verify_jwt") is False:
                add("V-AUTH-05", f"Edge Function {fn}", "verify_jwt = false : appelable sans JWT", "élevée")
        add("info", "supabase/config.toml", "réglages locaux seulement : comparer avec le Dashboard de prod (non versionné)", "info")
    # 5. Edge Functions
    for fn in glob.glob(os.path.join(R, "supabase", "functions", "*", "index.ts")):
        txt = open(fn, encoding="utf-8", errors="ignore").read()
        rel = os.path.relpath(fn, R)
        if re.search(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", txt):
            add("V-API-01", rel, "CORS « * »", "moyenne")
        secret = re.search(r"SERVICE_ROLE|SECRET_KEY", txt)
        lit_jwt = re.search(r"getUser\(|auth\.getClaims|Authorization", txt)
        if secret and not lit_jwt:
            add("V-AUTH-05", rel, "utilise la clé secrète (contourne RLS) sans lire l'identité de l'appelant", "élevée")
        if re.search(r"fetch\(\s*(?:req|body|params|url|input)", txt):
            add("V-API-05", rel, "fetch d'une URL qui semble venir de la requête (SSRF possible)", "moyenne")
    # 6. vercel.json
    vj = os.path.join(R, "vercel.json")
    if os.path.exists(vj):
        txt = open(vj, encoding="utf-8").read().lower()
        for h, cid in (("content-security-policy", "V-FE-02"), ("strict-transport-security", "V-FE-02"),
                       ("x-content-type-options", "V-FE-02")):
            if h not in txt:
                add(cid, "vercel.json", f"en-tête {h} absent", "moyenne" if h == "content-security-policy" else "info")
        if "frame-ancestors" not in txt and "x-frame-options" not in txt:
            add("V-FE-02", "vercel.json", "pas de protection contre l'intégration en iframe", "info")
        if "unsafe-inline" in txt or "unsafe-eval" in txt:
            add("V-FE-02", "vercel.json", "CSP avec unsafe-inline ou unsafe-eval", "moyenne")
    else:
        add("V-FE-02", "vercel.json", "absent : aucun en-tête de sécurité versionné (vérifier en observation passive)", "moyenne")
    # 7. React
    for f in suivis:
        if f.endswith((".tsx", ".jsx")) and not f.startswith("node_modules/"):
            txt = open(os.path.join(R, f), encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"dangerouslySetInnerHTML", txt):
                purif = "DOMPurify" in txt or "sanitize" in txt
                add("V-FE-01", f"{f}:{txt[:m.start()].count(chr(10)) + 1}",
                    "dangerouslySetInnerHTML" + (" (une désinfection est importée, à vérifier)" if purif else " sans désinfection visible"),
                    "info" if purif else "élevée")
            if re.search(r"rehype-raw|allowDangerousHtml|marked\(", txt):
                add("V-FE-01", f, "rendu Markdown avec HTML brut autorisé", "moyenne")

    ordre = {"élevée": 0, "moyenne": 1, "info": 2}
    S = sorted(set(S), key=lambda s: (ordre[s[3]], s[0], s[1]))
    L = ["# Contrôles statiques : configuration, secrets visibles, bundle", "",
         "Signaux **constatés dans les fichiers** (valeurs caviardées). Exploitabilité à confirmer en phase 6.", "",
         f"## Signaux ({len(S)})", "", "| Catalogue | Objet | Constat | Indication |", "|---|---|---|---|"]
    L += [f"| {c} | {o} | {t} | {i} |" for c, o, t, i in S]
    L += ["", "Non couvert ici : historique git complet (TruffleHog), dépendances (deps_check.py, osv-scanner), "
          "SAST par règles (Semgrep/Opengrep), advisors Supabase, réglages du Dashboard."]
    txt = "\n".join(L) + "\n"
    if a.sortie:
        os.makedirs(os.path.dirname(a.sortie) or ".", exist_ok=True)
        open(a.sortie, "w", encoding="utf-8").write(txt)
        print(f"Écrit : {a.sortie} ({len(S)} signaux)")
    else:
        print(txt)


if __name__ == "__main__":
    main()
