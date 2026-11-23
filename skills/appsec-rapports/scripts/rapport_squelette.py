#!/usr/bin/env python3
"""Génère les squelettes des rapports (synthèse direction, rapport technique, annexes) avec les chiffres réels.

Usage : rapport_squelette.py <racine-app> [--app "<nom>"] [--forcer]

Lit : security/07-findings/F-xxx.md, security/03-plan.yaml, security/03-asvs.csv, security/06-dynamique/
(matrice-resultats.json et resultats.md), security/00-cadrage.md, security/journal.md.
Écrit dans security/08-rapports/ : synthese-direction.md, rapport-technique.md, annexes.md.
Les chiffres (findings par priorité et statut, couverture ASVS, résultats de tests) sont calculés ; la prose est
laissée en « <à rédiger> ». N'écrase pas un fichier existant sans --forcer.
"""
import argparse
import csv
import datetime as dt
import glob
import json
import os
import re
import subprocess
from collections import Counter

import yaml


def champs(t):
    return {m.group(1).strip(): m.group(2).strip() for m in re.finditer(r"^- ([^:\n]+?) : (.*)$", t, re.M)}


def findings(d):
    out = []
    for f in sorted(glob.glob(os.path.join(d, "F-[0-9][0-9][0-9]*.md"))):
        t = open(f, encoding="utf-8").read()
        c = champs(t)
        m = re.match(r"# (F-\d{3}) : (.+)", t)
        sc = re.search(r"=\s*(\d{1,2}(?:\.\d)?)\)?\s*$", c.get("Sévérité", ""))
        out.append({"id": m.group(1) if m else os.path.basename(f)[:5], "titre": m.group(2).strip() if m else "",
                    "statut": c.get("Statut", "?"), "prio": (c.get("Priorité", "?").split() or ["?"])[0],
                    "sev": c.get("Sévérité", "").split("(")[0].strip(), "score": float(sc.group(1)) if sc else None,
                    "cat": c.get("Catégories", ""), "fichier": os.path.relpath(f, os.path.dirname(os.path.dirname(d)))})
    o = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Info": 4}
    out.sort(key=lambda r: (o.get(r["prio"], 9), -(r["score"] or 0)))
    return out


def couverture(sec):
    asvs_csv, plan = os.path.join(sec, "03-asvs.csv"), os.path.join(sec, "03-plan.yaml")
    if not (os.path.exists(asvs_csv) and os.path.exists(plan)):
        return None
    applic = {r["id"] for r in csv.DictReader(open(asvs_csv, encoding="utf-8"))
              if r.get("applicable", "").strip().lower() in ("oui", "o", "x", "yes")}
    cas = yaml.safe_load(open(plan, encoding="utf-8")) or []
    couverts = set()
    for tc in cas if isinstance(cas, list) else []:
        a = (tc.get("referentiels") or {}).get("asvs")
        for x in (a if isinstance(a, list) else [a]):
            if x:
                couverts.add(str(x) if str(x).startswith("v5") else "v5.0.0-" + str(x).lstrip("vV"))
    return (len(applic & couverts), len(applic), len(cas) if isinstance(cas, list) else 0) if applic else None


def tests(sec):
    res = Counter()
    for f in glob.glob(os.path.join(sec, "06-dynamique", "**", "matrice-resultats.json"), recursive=True):
        for r in json.load(open(f, encoding="utf-8")).get("resultats", []):
            res["matrice:" + r["statut"]] += 1
    rf = os.path.join(sec, "06-dynamique", "resultats.md")
    if os.path.exists(rf):
        for l in open(rf, encoding="utf-8"):
            m = re.match(r"\|\s*TC-[A-Z0-9-]+\s*\|[^|]*\|\s*(Réussi|Échec|Bloqué|Non exécuté|Non concluant)\s*\|", l, re.I)
            if m:
                res["cas:" + m.group(1).capitalize()] += 1
    return res


def ecrire(p, txt, forcer):
    if os.path.exists(p) and not forcer:
        print(f"Existe déjà, non écrasé : {p}")
        return
    open(p, "w", encoding="utf-8").write(txt)
    print(f"Écrit : {p}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("racine")
    ap.add_argument("--app")
    ap.add_argument("--forcer", action="store_true")
    a = ap.parse_args()
    R = os.path.abspath(a.racine)
    sec = os.path.join(R, "security")
    app = a.app or os.path.basename(R)
    F = findings(os.path.join(sec, "07-findings"))
    cp, cs = Counter(r["prio"] for r in F), Counter(r["statut"] for r in F)
    cov = couverture(sec)
    T = tests(sec)
    try:
        top = subprocess.run(["git", "-C", R, "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
        sha = (subprocess.run(["git", "-C", R, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
               if top and os.path.realpath(top) == os.path.realpath(R) else "") or "<commit de l'app : dépôt git absent>"
    except Exception:
        sha = "<commit>"
    cad = open(os.path.join(sec, "00-cadrage.md"), encoding="utf-8").read() if os.path.exists(os.path.join(sec, "00-cadrage.md")) else ""
    niveau = (re.search(r"ASVS[^\n]*?(L[123])", cad) or [None, "<L?>"])[1]
    date = dt.date.today().isoformat()
    os.makedirs(os.path.join(sec, "08-rapports"), exist_ok=True)

    cases = ", ".join(f"{k.split(':')[1]} {v}" for k, v in sorted(T.items()) if k.startswith("cas:")) or "non renseigné"
    matr = ", ".join(f"{k.split(':')[1]} {v}" for k, v in sorted(T.items()) if k.startswith("matrice:")) or "non exécutée"
    covtxt = f"{cov[0]}/{cov[1]} exigences applicables ({100 * cov[0] // max(cov[1], 1)} %)" if cov else "non calculée (03-asvs.csv ou 03-plan.yaml manquant)"
    ind = ["| Findings P0 | P1 | P2 | P3 | Info | Confirmés | Probables | Théoriques | Couverture ASVS " + niveau + " |",
           "|---|---|---|---|---|---|---|---|---|",
           f"| {cp.get('P0', 0)} | {cp.get('P1', 0)} | {cp.get('P2', 0)} | {cp.get('P3', 0)} | {cp.get('Info', 0)} | "
           f"{cs.get('Confirmé', 0)} | {cs.get('Probable', 0)} | {cs.get('Théorique', 0)} | {covtxt} |"]
    tab = ["| ID | Titre | Statut | Sévérité | CVSS 4.0 | Priorité |", "|---|---|---|---|---|---|"]
    tab += [f"| {r['id']} | {r['titre']} | {r['statut']} | {r['sev']} | {r['score'] if r['score'] is not None else 'n/a'} | {r['prio']} |" for r in F]
    majeurs = [r for r in F if r["prio"] in ("P0", "P1")][:5]

    synth = [f"# {app} : synthèse sécurité ({date})", "",
             "**Verdict** : <à rédiger : mise en prod oui / non / sous conditions, en une phrase>.", "",
             "## Posture globale", "<à rédiger : 2 à 3 phrases en langage métier>", "",
             "## Risques majeurs"]
    synth += [f"{i}. <à reformuler en langage métier> {r['titre']} ({r['prio']}, {r['statut'].lower()})" for i, r in enumerate(majeurs, 1)] or ["Aucun finding P0 ou P1."]
    synth += ["", "## Décision attendue", "<à rédiger>", "", "## Effort de correction", "<à estimer, avec l'incertitude>", "",
              "## Indicateurs", *ind, "", f"Cas de test : {cases}. Matrice d'autorisation : {matr}."]
    tech = [f"# {app} : rapport technique de sécurité ({date}, commit {sha})", "",
            "## 1. Périmètre et méthode", f"<à rédiger : périmètre, environnements, niveau ASVS {niveau}, référentiels et versions, outils et versions, dates>", "",
            "## 2. Résumé des résultats", *ind, "", f"Cas de test : {cases}. Matrice d'autorisation : {matr}.", "",
            "## 3. Tableau des findings", *tab, "",
            "## 4. Détail des findings"]
    for r in F:
        tech += [f"### {r['id']} : {r['titre']}", f"Repris de `{r['fichier']}` (statut, CVSS, preuve caviardée, impact, cause racine, mesure).", ""]
    tech += ["## 5. Testé sans anomalie", "<à rédiger à partir de 05-statique/synthese.md et 06-dynamique/resultats.md>", "",
             "## 6. Non testé et limites", "<à rédiger : non couvert et pourquoi, écarts labo/prod, hypothèses>", "",
             "## 7. Suite", "Pack de mitigation et plan de retest : appsec-mitigation-retest. Régression en CI."]
    ann = [f"# {app} : annexes ({date})", "", "- Plan de test exécuté : `security/03-plan.yaml`",
           "- Résultats statiques : `security/05-statique/`", "- Résultats dynamiques : `security/06-dynamique/`",
           "- Fiches finding : `security/07-findings/`", "- Journal : `security/journal.md`",
           "- Versions des outils et référentiels : <à compléter>"]
    ecrire(os.path.join(sec, "08-rapports", "synthese-direction.md"), "\n".join(synth) + "\n", a.forcer)
    ecrire(os.path.join(sec, "08-rapports", "rapport-technique.md"), "\n".join(tech) + "\n", a.forcer)
    ecrire(os.path.join(sec, "08-rapports", "annexes.md"), "\n".join(ann) + "\n", a.forcer)
    print(f"{len(F)} findings ({dict(cp)}), couverture : {covtxt}, cas : {cases}")


if __name__ == "__main__":
    main()
