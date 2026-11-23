#!/usr/bin/env python3
"""Récupère des identifiants ASVS 5.0.0, WSTG 4.2 et CWE dans leurs sources officielles.

But : ne jamais citer un identifiant de mémoire (règle 4.1 de la famille appsec-*).

Usage :
  ref_lookup.py asvs <mot-clé | id>  [--niveau N]
  ref_lookup.py asvs --chapitre V8   [--niveau N]
  ref_lookup.py wstg <mot-clé | id>
  ref_lookup.py cwe <numéro>
  Options communes : --json (sortie machine), --rafraichir (ignore le cache)

Le cache vit dans ~/.cache/appsec-refs (fichiers officiels, non modifiés).
Si la source est injoignable et qu'il n'y a pas de cache, le script le dit et sort en code 2 :
écrire alors « (à vérifier) » à côté de l'identifiant.
"""
import argparse
import csv
import html
import io
import json
import os
import re
import sys
import urllib.request

SOURCES = {
    "asvs": "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en/"
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv",
    "wstg": "https://raw.githubusercontent.com/OWASP/wstg/v4.2/checklist/checklist.json",
    "cwe": "https://cwe.mitre.org/data/definitions/{id}.html",
}
CACHE = os.path.expanduser("~/.cache/appsec-refs")


def fetch(url, cache_name=None, refresh=False):
    path = os.path.join(CACHE, cache_name) if cache_name else None
    if path and os.path.exists(path) and not refresh:
        with open(path, encoding="utf-8") as f:
            return f.read()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "appsec-ref-lookup"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read().decode("utf-8", errors="replace")
    except Exception as e:  # réseau bloqué, source déplacée...
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read()
        sys.stderr.write(f"Source injoignable : {url} ({e}). Marquer l'identifiant « (à vérifier) ».\n")
        sys.exit(2)
    if path:
        os.makedirs(CACHE, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
    return data


def norm_asvs(q):
    q = q.strip()
    m = re.fullmatch(r"(?:v5\.0\.0-)?[vV]?(\d+(?:\.\d+){0,2})", q)
    return ("V" + m.group(1)) if m else None


def asvs(args):
    rows = list(csv.DictReader(io.StringIO(fetch(SOURCES["asvs"], "asvs-5.0.0.csv", args.rafraichir))))
    out = []
    if args.chapitre:
        chap = norm_asvs(args.chapitre)
        out = [r for r in rows if r["req_id"] == chap or r["req_id"].startswith(chap + ".")]
    elif args.requete:
        q = " ".join(args.requete)
        rid = norm_asvs(q)
        if rid:
            out = [r for r in rows if r["req_id"] == rid or r["req_id"].startswith(rid + ".")]
        else:
            words = q.lower().split()
            out = [r for r in rows if all(w in (r["req_description"] + " " + r["section_name"]).lower() for w in words)]
    if args.niveau:
        out = [r for r in out if r["L"].strip().isdigit() and int(r["L"]) <= args.niveau]
    res = [{
        "id": "v5.0.0-" + r["req_id"].lstrip("V"),
        "id_csv": r["req_id"],
        "niveau": r["L"],
        "chapitre": f'{r["chapter_id"]} {r["chapter_name"]}',
        "section": f'{r["section_id"]} {r["section_name"]}',
        "exigence": r["req_description"],
    } for r in out]
    emit(res, SOURCES["asvs"], args.json)


def wstg(args):
    data = json.loads(fetch(SOURCES["wstg"], "wstg-4.2-checklist.json", args.rafraichir))
    q = " ".join(args.requete).lower()
    res = []
    for cat, c in data["categories"].items():
        for t in c["tests"]:
            hay = (t["id"] + " " + t["name"] + " " + " ".join(t.get("objectives", []))).lower()
            if t["id"].lower() == q or t["id"].lower().startswith(q) or all(w in hay for w in q.split()):
                res.append({
                    "id": t["id"],
                    "id_rapport": t["id"].replace("WSTG-", "WSTG-v42-"),
                    "categorie": cat,
                    "titre": t["name"],
                    "reference": t.get("reference", ""),
                })
    emit(res, SOURCES["wstg"], args.json)


def cwe(args):
    num = re.sub(r"\D", "", " ".join(args.requete))
    if not num:
        sys.exit("Donner un numéro CWE, ex. 639")
    url = SOURCES["cwe"].format(id=num)
    page = fetch(url, f"cwe-{num}.html", args.rafraichir)
    m = re.search(r"CWE-%s: ([^<]+?)\s*(?:\(\d[\d.]*\))?\s*</h2>" % num, page) or \
        re.search(r"CWE-%s: ([^<(]+)" % num, page)
    if not m:
        sys.stderr.write(f"CWE-{num} introuvable sur {url}. Marquer « (à vérifier) ».\n")
        sys.exit(2)
    emit([{"id": f"CWE-{num}", "titre": html.unescape(m.group(1)).strip(), "url": url}], url, args.json)


def emit(res, source, as_json):
    if as_json:
        print(json.dumps({"source": source, "resultats": res}, ensure_ascii=False, indent=2))
        return
    if not res:
        print(f"Aucun résultat. Source consultée : {source}")
        sys.exit(1)
    for r in res[:60]:
        print(" | ".join(str(v) for v in r.values()))
    if len(res) > 60:
        print(f"... {len(res) - 60} résultats de plus (affiner la requête ou utiliser --json)")
    print(f"Source : {source}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("referentiel", choices=["asvs", "wstg", "cwe"])
    p.add_argument("requete", nargs="*")
    p.add_argument("--chapitre", help="ASVS : chapitre entier, ex. V8")
    p.add_argument("--niveau", type=int, choices=[1, 2, 3], help="ASVS : niveau maximal")
    p.add_argument("--json", action="store_true")
    p.add_argument("--rafraichir", action="store_true")
    a = p.parse_args()
    if not a.requete and not a.chapitre:
        p.error("donner une requête ou --chapitre")
    {"asvs": asvs, "wstg": wstg, "cwe": cwe}[a.referentiel](a)


if __name__ == "__main__":
    main()
