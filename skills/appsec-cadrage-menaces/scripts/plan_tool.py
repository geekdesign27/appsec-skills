#!/usr/bin/env python3
"""Outils de la phase 3 (plan de test) de la famille appsec-*.

Usage :
  plan_tool.py asvs --niveau 2 [--chapitres V6,V8] [--compter]   > security/03-asvs.csv
  plan_tool.py valider security/03-plan.yaml [--menaces security/02-menaces.md] [--hors-ligne]
  plan_tool.py couverture security/03-plan.yaml [--asvs security/03-asvs.csv]

- asvs       : extrait les exigences ASVS 5.0.0 officielles jusqu'au niveau N, avec colonnes
               « applicable » et « raison » à remplir.
- valider    : contrôle le format partagé des cas de test (references/partage/formats.md, section 1),
               l'existence des identifiants ASVS et WSTG dans les sources officielles, la cohérence
               risque / environnement et l'existence des menaces citées.
- couverture : charge par lot et par priorité, couverture ASVS des exigences applicables.
Code de sortie 1 si des erreurs bloquantes sont trouvées.
"""
import argparse
import csv
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "partage"))
import ref_lookup  # noqa: E402  (scripts/partage/ref_lookup.py, partagé par la famille)

import yaml  # noqa: E402

CHAMPS = ["id", "titre", "objectif", "menaces", "referentiels", "cible", "preconditions", "mode",
          "outillage", "etapes", "resultat_attendu_securise", "critere_echec", "preuves",
          "risque_du_test", "environnements_autorises", "priorite", "effort_min", "regression"]
MODES = {"automatique", "semi", "manuel"}
RISQUES = {"faible", "moyen", "destructif"}
ENVS = {"labo", "staging", "prod"}
PRIOS = {"P0", "P1", "P2", "P3", "Info"}
RE_TC = re.compile(r"^TC-[A-Z]+-\d{3}$")
RE_TM = re.compile(r"^TM-\d{3}$")
RE_TOP10 = re.compile(r"^A(0[1-9]|10):2025$")
RE_API = re.compile(r"^API([1-9]|10):2023$")
RE_CWE = re.compile(r"^CWE-\d+$")


def asvs_rows(refresh=False):
    data = ref_lookup.fetch(ref_lookup.SOURCES["asvs"], "asvs-5.0.0.csv", refresh)
    return list(csv.DictReader(io.StringIO(data)))


def wstg_ids(refresh=False):
    data = json.loads(ref_lookup.fetch(ref_lookup.SOURCES["wstg"], "wstg-4.2-checklist.json", refresh))
    return {t["id"] for c in data["categories"].values() for t in c["tests"]}


def cwe_titre(num):
    """Titre officiel MITRE, '' si introuvable, None si source injoignable."""
    url = ref_lookup.SOURCES["cwe"].format(id=num)
    try:
        page = ref_lookup.fetch(url, f"cwe-{num}.html")
    except SystemExit:
        return None
    m = re.search(r"CWE-%s: ([^<(]+)" % num, page)
    return m.group(1).strip() if m else ""


def norm_asvs(x):
    m = re.fullmatch(r"(?:v5\.0\.0-)?[vV]?(\d+\.\d+\.\d+)", str(x).strip())
    return ("V" + m.group(1)) if m else None


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def cmd_asvs(a):
    rows = [r for r in asvs_rows() if int(r["L"]) <= a.niveau]
    if a.chapitres:
        keep = {c.strip().upper() for c in a.chapitres.split(",")}
        rows = [r for r in rows if r["chapter_id"].upper() in keep]
    if a.compter:
        print(f"{len(rows)} exigences ASVS 5.0.0 jusqu'au niveau L{a.niveau}")
        return 0
    w = csv.writer(sys.stdout)
    w.writerow(["id", "niveau", "chapitre", "section", "exigence", "applicable", "raison"])
    for r in rows:
        w.writerow(["v5.0.0-" + r["req_id"].lstrip("V"), r["L"], f'{r["chapter_id"]} {r["chapter_name"]}',
                    f'{r["section_id"]} {r["section_name"]}', r["req_description"], "", ""])
    sys.stderr.write(f"Source : {ref_lookup.SOURCES['asvs']}\n")
    return 0


def charger_plan(path):
    with open(path, encoding="utf-8") as f:
        plan = yaml.safe_load(f) or []
    if isinstance(plan, dict):
        plan = plan.get("cas") or plan.get("tests") or []
    return plan


def cmd_valider(a):
    plan = charger_plan(a.plan)
    erreurs, alertes = [], []
    asvs_ok = wstg_ok = None
    if not a.hors_ligne:
        try:
            asvs_ok = {r["req_id"] for r in asvs_rows()}
            wstg_ok = wstg_ids()
        except SystemExit:
            alertes.append("Sources officielles injoignables : identifiants ASVS/WSTG non vérifiés (marquer « à vérifier »).")
    tms = None
    if a.menaces and os.path.exists(a.menaces):
        tms = set(re.findall(r"TM-\d{3}", open(a.menaces, encoding="utf-8").read()))
    vus = set()
    for i, tc in enumerate(plan, 1):
        tid = tc.get("id", f"#{i}")
        def err(m):
            erreurs.append(f"{tid} : {m}")
        def warn(m):
            alertes.append(f"{tid} : {m}")
        for c in CHAMPS:
            if c not in tc or tc[c] in (None, "", []):
                err(f"champ manquant ou vide « {c} »")
        if not RE_TC.match(str(tc.get("id", ""))):
            err("identifiant hors format TC-<DOMAINE>-xxx")
        if tid in vus:
            err("identifiant en double")
        vus.add(tid)
        for tm in as_list(tc.get("menaces")):
            if not RE_TM.match(str(tm)):
                err(f"menace hors format TM-xxx : {tm}")
            elif tms is not None and tm not in tms:
                err(f"menace {tm} absente de {a.menaces}")
        if tc.get("mode") not in MODES:
            err(f"mode invalide : {tc.get('mode')}")
        if tc.get("risque_du_test") not in RISQUES:
            err(f"risque_du_test invalide : {tc.get('risque_du_test')}")
        envs = set(as_list(tc.get("environnements_autorises")))
        if not envs <= ENVS:
            err(f"environnement inconnu : {sorted(envs - ENVS)}")
        if tc.get("risque_du_test") == "destructif" and envs != {"labo"}:
            err("test destructif autorisé hors labo (règle 2.1 : labo uniquement)")
        if tc.get("risque_du_test") == "moyen" and "prod" in envs:
            err("test à risque moyen autorisé en prod (prod = observation passive)")
        if "staging" in envs:
            warn("autorisé en staging : exigera la porte G3")
        if tc.get("priorite") not in PRIOS:
            err(f"priorité invalide : {tc.get('priorite')}")
        if not isinstance(tc.get("effort_min"), (int, float)):
            err("effort_min doit être un nombre de minutes")
        refs = tc.get("referentiels") or {}
        if not isinstance(refs, dict):
            err("referentiels doit être un dictionnaire")
            refs = {}
        for x in as_list(refs.get("asvs")):
            if "<" in str(x) or "vérifier" in str(x):
                warn(f"ASVS non renseigné ou à vérifier : {x}")
                continue
            n = norm_asvs(x)
            if not n:
                err(f"ASVS hors format v5.0.0-x.y.z : {x}")
            elif asvs_ok is not None and n not in asvs_ok:
                err(f"ASVS {x} introuvable dans le CSV officiel 5.0.0")
        for x in as_list(refs.get("wstg")):
            if "<" in str(x) or "vérifier" in str(x):
                warn(f"WSTG non renseigné ou à vérifier : {x}")
                continue
            w = str(x).replace("WSTG-v42-", "WSTG-")
            if wstg_ok is not None and w not in wstg_ok:
                err(f"WSTG {x} introuvable dans la checklist officielle v4.2")
        for x in as_list(refs.get("top10")):
            if not RE_TOP10.match(str(x)):
                err(f"Top 10 hors format Axx:2025 : {x}")
        for x in as_list(refs.get("api")):
            if not RE_API.match(str(x)):
                err(f"API Top 10 hors format APIx:2023 : {x}")
        for x in as_list(refs.get("cwe")):
            if not RE_CWE.match(str(x)):
                err(f"CWE hors format CWE-n : {x}")
            elif not a.hors_ligne:
                t = cwe_titre(str(x)[4:])
                if t is None:
                    warn(f"{x} non vérifié (MITRE injoignable) : marquer « à vérifier »")
                elif t == "":
                    err(f"{x} introuvable sur cwe.mitre.org")
                elif t.startswith("DEPRECATED"):
                    err(f"{x} est déprécié chez MITRE ({t})")
    print(f"{len(plan)} cas de test lus dans {a.plan}")
    print(f"Erreurs : {len(erreurs)}")
    for e in erreurs:
        print("  ✗ " + e)
    print(f"Alertes : {len(alertes)}")
    for w in alertes:
        print("  ! " + w)
    return 1 if erreurs else 0


def cmd_couverture(a):
    plan = charger_plan(a.plan)
    lots, prios, total = {}, {}, 0
    couverts = set()
    for tc in plan:
        lot = str(tc.get("lot", "sans lot"))
        e = tc.get("effort_min") or 0
        lots.setdefault(lot, [0, 0])
        lots[lot][0] += 1
        lots[lot][1] += e
        prios[tc.get("priorite", "?")] = prios.get(tc.get("priorite", "?"), 0) + 1
        total += e
        for x in as_list((tc.get("referentiels") or {}).get("asvs")):
            n = norm_asvs(x)
            if n:
                couverts.add(n)
    print(f"Cas de test : {len(plan)}   Charge totale : {total} min ({total / 60:.1f} h)")
    print("Par lot :")
    for k in sorted(lots):
        print(f"  lot {k} : {lots[k][0]} cas, {lots[k][1]} min")
    print("Par priorité : " + ", ".join(f"{k} {v}" for k, v in sorted(prios.items())))
    if a.asvs and os.path.exists(a.asvs):
        rows = list(csv.DictReader(open(a.asvs, encoding="utf-8")))
        applic = {norm_asvs(r["id"]) for r in rows if r.get("applicable", "").strip().lower() in ("oui", "o", "yes", "x")}
        non_tranche = sum(1 for r in rows if not r.get("applicable", "").strip())
        if applic:
            c = applic & couverts
            print(f"Couverture ASVS : {len(c)}/{len(applic)} exigences applicables ({100 * len(c) / len(applic):.0f} %)")
            manq = sorted(applic - couverts, key=lambda s: [int(p) for p in s[1:].split('.')])
            if manq:
                print("  Non couvertes : " + ", ".join("v5.0.0-" + m[1:] for m in manq[:40]) + (" ..." if len(manq) > 40 else ""))
        else:
            print("Couverture ASVS : aucune exigence marquée applicable dans " + a.asvs)
        if non_tranche:
            print(f"  {non_tranche} exigences sans décision « applicable » (oui/non) à trancher")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    x = s.add_parser("asvs")
    x.add_argument("--niveau", type=int, choices=[1, 2, 3], required=True)
    x.add_argument("--chapitres")
    x.add_argument("--compter", action="store_true")
    v = s.add_parser("valider")
    v.add_argument("plan")
    v.add_argument("--menaces")
    v.add_argument("--hors-ligne", action="store_true")
    c = s.add_parser("couverture")
    c.add_argument("plan")
    c.add_argument("--asvs")
    a = p.parse_args()
    sys.exit({"asvs": cmd_asvs, "valider": cmd_valider, "couverture": cmd_couverture}[a.cmd](a))


if __name__ == "__main__":
    main()
