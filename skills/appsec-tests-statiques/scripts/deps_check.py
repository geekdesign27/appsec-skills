#!/usr/bin/env python3
"""Chaîne d'approvisionnement npm : lockfile, scripts d'installation, paquets suspects (phase 5).

Usage :
  deps_check.py <racine-app> [--registre] [--sortie security/05-statique/dependances.md]

Hors ligne : lockfile présent, scripts postinstall/preinstall du projet et des dépendances (package-lock v2/v3),
dépendances Git/URL, versions non épinglées dans package.json.
Avec --registre : interroge registry.npmjs.org (métadonnées publiques seulement) pour signaler les paquets directs
publiés il y a moins de 90 jours, à mainteneur unique, ou au nom proche d'un paquet très connu
(signaux de slopsquatting V-SC-01). Ce sont des signaux, pas des verdicts : compléter avec Socket CLI et osv-scanner.
"""
import argparse
import datetime as dt
import json
import os
import re
import urllib.request

CONNUS = ["react", "react-dom", "vite", "typescript", "tailwindcss", "@supabase/supabase-js", "zod", "axios",
          "lodash", "date-fns", "dayjs", "express", "next", "vue", "jsonwebtoken", "bcrypt", "dotenv", "uuid",
          "react-router-dom", "@tanstack/react-query", "clsx", "dompurify", "marked", "react-markdown", "openai",
          "@anthropic-ai/sdk", "stripe", "zustand", "framer-motion", "lucide-react", "recharts", "i18next"]


def distance(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        c = [i]
        for j, cb in enumerate(b, 1):
            c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (ca != cb)))
        p = c
    return p[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("racine")
    ap.add_argument("--registre", action="store_true")
    ap.add_argument("--sortie")
    a = ap.parse_args()
    R = os.path.abspath(a.racine)
    S = []
    add = lambda c, o, t, i: S.append((c, o, t, i))
    pj = os.path.join(R, "package.json")
    if not os.path.exists(pj):
        add("info", "package.json", "absent : pas de projet npm à la racine", "info")
        deps = {}
    else:
        p = json.load(open(pj, encoding="utf-8"))
        deps = {**p.get("dependencies", {}), **p.get("devDependencies", {})}
        for k in ("preinstall", "install", "postinstall", "prepare"):
            if k in p.get("scripts", {}):
                add("V-SC-03", "package.json", f"script {k} du projet : {p['scripts'][k]}", "info")
        for n, v in deps.items():
            if re.match(r"^(git\+|git:|github:|https?:|file:)", str(v)) or "/" in str(v) and not str(v).startswith("@"):
                add("V-SC-03", n, f"dépendance hors registre : {v}", "moyenne")
            elif str(v) in ("*", "latest", ""):
                add("V-SC-03", n, f"version non bornée : « {v} »", "moyenne")
    locks = [f for f in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock") if os.path.exists(os.path.join(R, f))]
    if not locks and deps:
        add("V-SC-03", "lockfile", "aucun lockfile : versions installées non reproductibles", "moyenne")
    if "package-lock.json" in locks:
        lk = json.load(open(os.path.join(R, "package-lock.json"), encoding="utf-8"))
        scripts = [k.replace("node_modules/", "") for k, v in (lk.get("packages") or {}).items() if k and v.get("hasInstallScript")]
        if scripts:
            add("V-SC-03", "package-lock.json", f"{len(scripts)} dépendances avec script d'installation : {', '.join(sorted(scripts)[:15])}"
                + (" ..." if len(scripts) > 15 else ""), "info")
    for n in deps:
        for c in CONNUS:
            d = distance(n.lower(), c)
            if n != c and 0 < d <= 1 and len(c) > 4:
                add("V-SC-01", n, f"nom très proche de « {c} » (typosquat possible)", "élevée")
    if a.registre:
        now = dt.datetime.now(dt.timezone.utc)
        hors_registre = re.compile(r"^(git\+|git:|github:|https?:|file:|link:|workspace:)")
        for n in sorted(deps):
            if hors_registre.match(str(deps[n])):
                continue
            try:
                with urllib.request.urlopen(f"https://registry.npmjs.org/{n.replace('/', '%2F')}", timeout=20) as r:
                    m = json.load(r)
            except Exception as e:
                add("V-SC-01", n, f"introuvable sur le registre npm ({str(e)[:60]}) : paquet halluciné ?", "élevée")
                continue
            cree = m.get("time", {}).get("created")
            if cree:
                age = (now - dt.datetime.fromisoformat(cree.replace("Z", "+00:00"))).days
                if age < 90:
                    add("V-SC-01", n, f"paquet créé il y a {age} jours", "moyenne")
            if len(m.get("maintainers", [])) <= 1 and n not in CONNUS:
                add("info", n, "mainteneur unique", "info")
            if m.get("deprecated") or (m.get("versions", {}).get(m.get("dist-tags", {}).get("latest", ""), {}) or {}).get("deprecated"):
                add("V-SC-02", n, "version courante dépréciée", "moyenne")
    ordre = {"élevée": 0, "moyenne": 1, "info": 2}
    S = sorted(set(S), key=lambda s: (ordre[s[3]], s[0], s[1]))
    L = ["# Chaîne d'approvisionnement npm", "", f"Lockfile : {', '.join(locks) or 'aucun'}. Dépendances directes : {len(deps)}."
         + (" Registre npm interrogé." if a.registre else " Registre non interrogé (option --registre)."), "",
         f"## Signaux ({len(S)})", "", "| Catalogue | Objet | Constat | Indication |", "|---|---|---|---|"]
    L += [f"| {c} | {o} | {t} | {i} |" for c, o, t, i in S]
    L += ["", "Compléter par : osv-scanner (CVE connues, puis EPSS/KEV pour les CVE trouvées), Socket CLI (paquets malveillants)."]
    txt = "\n".join(L) + "\n"
    if a.sortie:
        os.makedirs(os.path.dirname(a.sortie) or ".", exist_ok=True)
        open(a.sortie, "w", encoding="utf-8").write(txt)
        print(f"Écrit : {a.sortie} ({len(S)} signaux)")
    else:
        print(txt)


if __name__ == "__main__":
    main()
