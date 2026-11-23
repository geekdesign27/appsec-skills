#!/usr/bin/env python3
"""Dépose dans le Storage LOCAL des fichiers marqués par tenant (section « fichiers » de identites.yaml).

Usage (depuis la racine de l'app, après « supabase db reset ») :
  python3 security/labo/labo_fichiers.py [--env security/labo/.env.lab] [--identites security/labo/identites.yaml]

Chaque fichier contient son marqueur (SECRET-TENANT-<code>-1nn) : si un autre tenant peut le lire ou le lister,
la fuite est indiscutable. Le dépôt utilise la clé secrète LOCALE lue dans « supabase status -o env » : elle
contourne les policies, c'est voulu pour préparer le terrain. Le script refuse toute API non locale.
"""
import argparse
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

NS = uuid.UUID("6f1c3c1e-3b7a-4c55-9d0e-6c1a5b0e0a11")  # identique à labo_init.py


def lab_uuid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", default="security/labo/.env.lab")
    p.add_argument("--identites", default="security/labo/identites.yaml")
    a = p.parse_args()

    env = dict(re.findall(r"^([A-Z_]+)=(.*)$", open(a.env, encoding="utf-8").read(), re.M))
    url = env.get("SUPABASE_URL", "")
    if urllib.parse.urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        sys.exit(f"ARRÊT : API non locale ({url!r}).")
    cfg = yaml.safe_load(open(a.identites, encoding="utf-8"))
    specs = cfg.get("fichiers") or []
    if not specs:
        print("Aucune section « fichiers » dans identites.yaml : rien à déposer.")
        return 0
    try:
        st = subprocess.run(["supabase", "status", "-o", "env"], capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        sys.exit(f"supabase status indisponible : {e}")
    stv = {k: v.strip('"') for k, v in re.findall(r"^([A-Z_]+)=(.*)$", st, re.M)}
    if stv.get("API_URL") and urllib.parse.urlparse(stv["API_URL"]).hostname not in ("127.0.0.1", "localhost"):
        sys.exit("ARRÊT : supabase status ne pointe pas sur une stack locale.")
    cle = stv.get("SECRET_KEY") or stv.get("SERVICE_ROLE_KEY")
    if not cle:
        sys.exit("Clé secrète locale introuvable dans « supabase status -o env » (stack démarrée ?).")

    app = cfg.get("app", "")
    ok = 0
    for spec in specs:
        bucket = spec["bucket"]
        for t in cfg["tenants"]:
            code = str(t["code"])
            tid = lab_uuid(app, "tenant", code)
            for n in range(1, int(spec.get("par_tenant", 1)) + 1):
                mk = f"SECRET-TENANT-{code}-{100 + n:03d}"
                chemin = spec.get("chemin", "{tenant_id}/{marqueur}.txt").format(
                    tenant_id=tid, tenant_code=code, marqueur=mk, n=n)
                corps = f"{mk}\nFichier de test du laboratoire AppSec. Données fictives.\n".encode()
                req = urllib.request.Request(
                    f"{url}/storage/v1/object/{bucket}/{urllib.parse.quote(chemin)}", data=corps, method="POST",
                    headers={"apikey": cle, "Authorization": "Bearer " + cle, "Content-Type": "text/plain",
                             "x-upsert": "true"})
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        ok += r.status in (200, 201)
                        print(f"OK    {bucket}/{chemin}")
                except urllib.error.HTTPError as e:
                    print(f"ÉCHEC {bucket}/{chemin} → {e.code} {e.read().decode()[:120]}")
    print(f"{ok} fichiers marqués déposés.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
