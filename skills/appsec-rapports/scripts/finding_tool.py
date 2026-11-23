#!/usr/bin/env python3
"""Fiches finding F-xxx au format partagé (references/partage/formats.md, section 2) : créer, valider, agréger.

Usage :
  finding_tool.py nouveau security/07-findings --titre "Lecture inter-tenant de la table audits"
  finding_tool.py valider security/07-findings [--hors-ligne]
  finding_tool.py tableau security/07-findings [--sortie security/07-findings/index.md]

valider : titre « # F-xxx : … », champs obligatoires, statut (Confirmé, Probable, Théorique), vecteur CVSS 4.0
recalculé et comparé au score écrit, priorité (P0 à P3, Info), sections obligatoires, renvoi à une mesure M-xxx,
identifiants ASVS et CWE vérifiés dans les sources officielles, absence de secret en clair.
tableau : liste triée par priorité puis score, indicateurs (findings par priorité et par statut).
Code de sortie 1 si une fiche est invalide.
"""
import argparse
import glob
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ICI, "partage"))
sys.path.insert(0, ICI)

GABARIT = """# {id} : {titre}

- Statut : <Confirmé | Probable | Théorique>
- Sévérité : <Critique | Élevée | Moyenne | Faible> (CVSS 4.0 : <vecteur complet> = <score>)
- Priorité : <P0 | P1 | P2 | P3 | Info>
- Catégories : <Axx:2025>, <APIx:2023 si API>, <CWE-n vérifié>
- Exigences ASVS non satisfaites : <v5.0.0-x.y.z vérifiés>
- Tests : <TC-xxx (échec)>
- Actif : <table, fonction, fichier>

## Constat
Une phrase par fait. Ce qui a été observé, où, quand.

## Preuve
Requête et réponse caviardées, capture, commit testé.

## Impact
Ce qu'un attaquant obtient, pour qui, avec quelles conséquences (dont nLPD).

## Cause racine
<cause>

## Recommandation (résumé)
Renvoi vers M-{num} du pack de mitigation.

## Limites
Ce qui n'a pas été testé ou reste incertain.
"""
SECTIONS = ["Constat", "Preuve", "Impact", "Cause racine", "Recommandation (résumé)", "Limites"]
CHAMPS = ["Statut", "Sévérité", "Priorité", "Catégories", "Exigences ASVS non satisfaites", "Tests", "Actif"]
STATUTS = {"Confirmé", "Probable", "Théorique"}
PRIOS = {"P0", "P1", "P2", "P3", "Info"}
SECRET = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|sb_secret_[A-Za-z0-9_\-]{12,}|"
                    r"postgres(?:ql)?://[^:\s/]+:[^@\s\[]{4,}@")


def champs(txt):
    return {m.group(1).strip(): m.group(2).strip() for m in re.finditer(r"^- ([^:\n]+?) : (.*)$", txt, re.M)}


def lire(dossier):
    fs = sorted(glob.glob(os.path.join(dossier, "F-[0-9][0-9][0-9]*.md")))
    return [(f, open(f, encoding="utf-8").read()) for f in fs]


def cmd_nouveau(a):
    os.makedirs(a.dossier, exist_ok=True)
    nums = [int(re.search(r"F-(\d{3})", os.path.basename(f)).group(1)) for f, _ in lire(a.dossier)]
    n = max(nums, default=0) + 1
    fid = f"F-{n:03d}"
    p = os.path.join(a.dossier, f"{fid}.md")
    open(p, "w", encoding="utf-8").write(GABARIT.format(id=fid, titre=a.titre, num=f"{n:03d}"))
    print(f"Créé : {p}")


def cmd_valider(a):
    import cvss_calc
    asvs_ok = None
    if not a.hors_ligne:
        try:
            import ref_lookup
            import csv
            import io
            asvs_ok = {r["req_id"] for r in csv.DictReader(io.StringIO(ref_lookup.fetch(ref_lookup.SOURCES["asvs"], "asvs-5.0.0.csv")))}
        except SystemExit:
            print("! ASVS non vérifiable (source injoignable)")
    fiches = lire(a.dossier)
    total = 0
    for f, t in fiches:
        err = []
        nom = os.path.basename(f)
        m = re.match(r"# (F-\d{3}) : .+", t)
        if not m:
            err.append("titre hors format « # F-xxx : titre »")
        elif not nom.startswith(m.group(1)):
            err.append(f"identifiant {m.group(1)} différent du nom de fichier")
        if "<" in t and re.search(r"<(Confirmé|vecteur|P0|Axx|v5\.0\.0|TC-xxx|table|cause)", t):
            err.append("gabarit non rempli (valeurs <…> restantes)")
        c = champs(t)
        for k in CHAMPS:
            if k not in c or not c[k]:
                err.append(f"champ manquant : {k}")
        if c.get("Statut") and c["Statut"] not in STATUTS:
            err.append(f"statut invalide : {c['Statut']}")
        if c.get("Priorité") and c["Priorité"].split()[0] not in PRIOS:
            err.append(f"priorité invalide : {c['Priorité']}")
        sev = c.get("Sévérité", "")
        mv = re.search(r"(CVSS:4\.0/[A-Z:/]+)\s*=\s*(\d{1,2}(?:\.\d)?)", sev)
        if mv:
            try:
                r = cvss_calc.calc(mv.group(1))
                if abs(r["score"] - float(mv.group(2))) > 0.05:
                    err.append(f"score CVSS écrit {mv.group(2)} ≠ calculé {r['score']} pour {mv.group(1)}")
                if not sev.lower().startswith(r["severite"].lower()):
                    err.append(f"sévérité écrite « {sev.split('(')[0].strip()} » ≠ calculée « {r['severite']} »")
            except SystemExit as e:
                err.append(str(e))
            except Exception as e:
                err.append(f"vecteur CVSS invalide : {e}")
        elif c.get("Statut") == "Confirmé":
            err.append("finding confirmé sans vecteur CVSS 4.0 complet « CVSS 4.0 : <vecteur> = <score> »")
        for s in SECTIONS:
            if not re.search(r"^## " + re.escape(s) + r"\s*$", t, re.M):
                err.append(f"section manquante : {s}")
        if not re.search(r"\bM-\d{3}\b", t):
            err.append("pas de renvoi à une mesure M-xxx")
        if c.get("Statut") == "Confirmé" and not re.search(r"\bTC-[A-Z0-9]+-\d{2,3}\b", c.get("Tests", "")):
            err.append("finding confirmé sans cas de test TC-xxx")
        for x in re.findall(r"v5\.0\.0-(\d+\.\d+\.\d+)", t):
            if asvs_ok is not None and "V" + x not in asvs_ok:
                err.append(f"ASVS v5.0.0-{x} introuvable dans le CSV officiel")
        if SECRET.search(t):
            err.append("secret ou jeton en clair dans la fiche (à caviarder)")
        total += bool(err)
        print(("✗ " if err else "✓ ") + nom + ("" if not err else ""))
        for e in err:
            print("    - " + e)
    print(f"{len(fiches)} fiches, {total} invalides. Vérifier aussi chaque CWE : ref_lookup.py cwe <n>.")
    sys.exit(1 if total else 0)


def cmd_tableau(a):
    rows = []
    for f, t in lire(a.dossier):
        c = champs(t)
        m = re.match(r"# (F-\d{3}) : (.+)", t)
        sc = re.search(r"=\s*(\d{1,2}(?:\.\d)?)\)?\s*$", c.get("Sévérité", ""))
        rows.append({"id": m.group(1) if m else os.path.basename(f), "titre": m.group(2) if m else "",
                     "statut": c.get("Statut", "?"), "prio": (c.get("Priorité", "?").split() or ["?"])[0],
                     "score": float(sc.group(1)) if sc else -1, "sev": c.get("Sévérité", "").split("(")[0].strip()})
    ordre = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Info": 4}
    rows.sort(key=lambda r: (ordre.get(r["prio"], 9), -r["score"]))
    from collections import Counter
    cp, cs = Counter(r["prio"] for r in rows), Counter(r["statut"] for r in rows)
    L = ["# Findings : tableau de synthèse", "",
         "**Par priorité** : " + ", ".join(f"{k} {cp.get(k, 0)}" for k in ["P0", "P1", "P2", "P3", "Info"]),
         "**Par statut** : " + ", ".join(f"{k} {cs.get(k, 0)}" for k in ["Confirmé", "Probable", "Théorique"]), "",
         "| ID | Titre | Statut | Sévérité | CVSS 4.0 | Priorité |", "|---|---|---|---|---|---|"]
    L += [f"| {r['id']} | {r['titre']} | {r['statut']} | {r['sev']} | {r['score'] if r['score'] >= 0 else 'n/a'} | {r['prio']} |" for r in rows]
    txt = "\n".join(L) + "\n"
    if a.sortie:
        open(a.sortie, "w", encoding="utf-8").write(txt)
        print(f"Écrit : {a.sortie}")
    else:
        print(txt)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = ap.add_subparsers(dest="cmd", required=True)
    n = s.add_parser("nouveau")
    n.add_argument("dossier")
    n.add_argument("--titre", required=True)
    v = s.add_parser("valider")
    v.add_argument("dossier")
    v.add_argument("--hors-ligne", action="store_true")
    t = s.add_parser("tableau")
    t.add_argument("dossier")
    t.add_argument("--sortie")
    a = ap.parse_args()
    {"nouveau": cmd_nouveau, "valider": cmd_valider, "tableau": cmd_tableau}[a.cmd](a)


if __name__ == "__main__":
    main()
