#!/usr/bin/env python3
"""Calcul CVSS 4.0 (FIRST) pour les findings de la famille appsec-*.

Usage :
  cvss_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"   score, sévérité, nomenclature
  cvss_calc.py --json "<vecteur>"
  cvss_calc.py --metriques                                                          aide-mémoire des métriques

Moteur : bibliothèque Python « cvss » (PyPI, version 3.6 vérifiée le 23.11.2026). Sa table des 270 macro-vecteurs
est identique à celle du calculateur de référence FIRST (cvss_lookup.js), et elle retrouve les scores publiés dans
les exemples officiels FIRST v4.0 (54 sur 59 ; les 5 autres sont des incohérences internes de la page d'exemples).
Installation si absente :  pip install cvss==3.6
Nomenclature FIRST : CVSS-B (base seule), CVSS-BT (+ menace), CVSS-BE (+ environnement), CVSS-BTE (les deux).
"""
import json
import sys

AIDE = """Métriques de base (exploitabilité)
  AV  vecteur d'attaque      N réseau | A adjacent | L local | P physique
  AC  complexité             L faible | H élevée
  AT  conditions préalables  N aucune | P présentes (ex. course, configuration particulière)
  PR  privilèges requis      N aucun | L compte simple | H compte privilégié
  UI  interaction            N aucune | P passive | A active (la victime doit agir)
Impact sur le système vulnérable (l'app)          VC VI VA   H élevé | L faible | N aucun
Impact sur les systèmes suivants (autres tenants, SI) SC SI SA H | L | N   (SI/SA : S = sécurité des personnes, en env.)
Menace  E  exploit : A attaqué/PoC public fiable | P PoC | U non signalé | X non défini (= A, pire cas)
Environnement  CR IR AR exigences C/I/D : H | M | L ;  MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA (métriques modifiées)
Repères pour les apps de PA (à justifier dans chaque finding) :
  - Lecture inter-tenant par API avec un compte simple : AV:N/AC:L/AT:N/PR:L/UI:N, VC:H (données d'un autre client).
  - Même chose sans compte (clé publishable seule) : PR:N.
  - Données de santé (nLPD sensibles) : CR:H dans l'environnement.
  - XSS stockée : UI:P ou UI:A selon le déclenchement ; impact surtout sur le système suivant (navigateur) SC/SI.
"""


def calc(vecteur):
    try:
        import cvss
    except ImportError:
        sys.exit("Bibliothèque « cvss » absente : pip install cvss==3.6")
    v = cvss.CVSS4(vecteur.strip())
    metr = dict(p.split(":") for p in v.clean_vector().split("/")[1:])
    menace = any(k == "E" and x != "X" for k, x in metr.items())
    env = any(k in ("CR", "IR", "AR") or k.startswith("M") for k, x in metr.items() if x != "X")
    nom = "CVSS-B" + ("T" if menace else "") + ("E" if env else "")
    nom = {"CVSS-B": "CVSS-B", "CVSS-BT": "CVSS-BT", "CVSS-BE": "CVSS-BE", "CVSS-BTE": "CVSS-BTE"}[nom]
    sev = {"None": "Aucune", "Low": "Faible", "Medium": "Moyenne", "High": "Élevée", "Critical": "Critique"}
    return {"vecteur": v.clean_vector(), "score": float(v.base_score), "severite": sev.get(v.severity, v.severity),
            "nomenclature": nom}


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return
    if a[0] == "--metriques":
        print(AIDE)
        return
    js = a[0] == "--json"
    vec = a[1] if js else a[0]
    try:
        r = calc(vec)
    except Exception as e:
        sys.exit(f"Vecteur CVSS 4.0 invalide : {e}")
    if js:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print(f"{r['nomenclature']} {r['score']} ({r['severite']})")
        print(r["vecteur"])


if __name__ == "__main__":
    main()
