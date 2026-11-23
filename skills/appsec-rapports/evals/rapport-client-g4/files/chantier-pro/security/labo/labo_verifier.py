#!/usr/bin/env python3
"""Vérifie que le laboratoire AppSec est sain AVANT de lancer des tests (profil, section 7).

Usage (depuis la racine de l'app) :
  python3 security/labo/labo_verifier.py [--env security/labo/.env.lab] [--publishable <clé>] [--sonde table:colonne]

Contrôles :
  1. L'URL de l'API est locale (127.0.0.1 ou localhost). Sinon : arrêt immédiat.
  2. Aucune valeur de production dans .env.lab ni dans l'environnement (URL *.supabase.co, clé secrète,
     SUPABASE_YES exporté).
  3. L'API d'authentification répond (/auth/v1/health).
  4. Chaque identité de security/labo/identites.md se connecte (mot de passe de test) et reçoit un JWT.
  5. Option --sonde : avec son JWT, chaque identité lit au moins un marqueur de SON tenant dans table.colonne
     (contrôle que le seed est en place, ce n'est pas encore un test d'isolation).
La clé publishable locale est lue dans --publishable, $SUPABASE_PUBLISHABLE_KEY ou « supabase status -o env ».
Code de sortie : 0 si tout est vert, 1 sinon.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

PROD = [r"https?://[a-z0-9]{20}\.supabase\.co", r"sb_secret_[A-Za-z0-9_-]{20,}"]


def lire_env(path):
    env = {}
    if os.path.exists(path):
        for l in open(path, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1)
                env[k.strip()] = v.strip().strip('"')
    return env


def statut_supabase():
    try:
        out = subprocess.run(["supabase", "status", "-o", "env"], capture_output=True, text=True, timeout=60).stdout
    except Exception:
        return {}
    return {k: v.strip('"') for k, v in re.findall(r'^([A-Z_]+)=(.*)$', out, re.M)}


def requete(url, cle, data=None, jwt=None):
    h = {"apikey": cle, "Content-Type": "application/json"}
    if jwt:
        h["Authorization"] = "Bearer " + jwt
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", default="security/labo/.env.lab")
    p.add_argument("--identites", default="security/labo/identites.md")
    p.add_argument("--publishable")
    p.add_argument("--sonde", help="table:colonne contenant les marqueurs SECRET-TENANT-<code>-xxx")
    a = p.parse_args()

    ok = True
    def ligne(etat, msg):
        nonlocal ok
        ok &= etat
        print(("OK   " if etat else "ÉCHEC") + " " + msg)

    env = lire_env(a.env)
    url = env.get("SUPABASE_URL", "")
    host = urllib.parse.urlparse(url).hostname
    if host not in ("127.0.0.1", "localhost"):
        print(f"ARRÊT : SUPABASE_URL n'est pas locale ({url!r}). Le labo ne tourne que sur la machine locale.")
        sys.exit(1)
    ligne(True, f"API locale : {url}")

    brut = open(a.env, encoding="utf-8").read() if os.path.exists(a.env) else ""
    fuite = [m for m in PROD if re.search(m, brut)]
    ligne(not fuite, ".env.lab sans valeur de production" + (f" (trouvé : {fuite})" if fuite else ""))
    ligne(not os.environ.get("SUPABASE_YES"), "SUPABASE_YES non exporté (sinon la CLI ne demande plus confirmation)")

    st = statut_supabase()
    cle = a.publishable or os.environ.get("SUPABASE_PUBLISHABLE_KEY") or st.get("PUBLISHABLE_KEY") or st.get("ANON_KEY")
    if not cle:
        ligne(False, "clé publishable locale introuvable (lancer « supabase start » ou passer --publishable)")
        sys.exit(1)
    if st.get("API_URL"):
        ligne(urllib.parse.urlparse(st["API_URL"]).hostname in ("127.0.0.1", "localhost"),
              f"supabase status pointe sur une API locale ({st['API_URL']})")

    code, _ = requete(url + "/auth/v1/health", cle)
    ligne(code == 200, f"Auth répond (/auth/v1/health → {code})")

    mdp = env.get("LABO_MOT_DE_PASSE", "")
    ids = []
    if os.path.exists(a.identites):
        for l in open(a.identites, encoding="utf-8"):
            m = re.match(r"\|\s*([a-z0-9]+-[a-z0-9_]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(\S+@\S+)\s*\|", l)
            if m:
                ids.append((m.group(1), m.group(2), m.group(4)))
    ligne(bool(ids), f"{len(ids)} identités lues dans {a.identites}")

    table = col = None
    if a.sonde:
        table, col = a.sonde.split(":")
        table = table.split(".")[-1]
    for ident, tenant, email in ids:
        code, corps = requete(url + "/auth/v1/token?grant_type=password", cle, {"email": email, "password": mdp})
        jwt = json.loads(corps).get("access_token") if code == 200 else None
        ligne(bool(jwt), f"connexion {ident} ({email}) → {code}")
        if jwt and table:
            q = f"{url}/rest/v1/{table}?select={col}&{col}=like.SECRET-TENANT-{urllib.parse.quote(tenant)}-*&limit=1"
            c2, b2 = requete(q, cle, jwt=jwt)
            vu = c2 == 200 and f"SECRET-TENANT-{tenant}-" in b2
            ligne(vu, f"  {ident} voit un marqueur de son tenant {tenant} dans {table}.{col} → {c2}")

    print("Labo prêt." if ok else "Labo NON prêt : corriger les échecs avant tout test.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
