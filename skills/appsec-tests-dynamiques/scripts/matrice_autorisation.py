#!/usr/bin/env python3
"""Matrice d'autorisation : chaque identité x chaque ressource x chaque action, par l'API directe (phase 6).

Usage (depuis la racine de l'app, labo démarré et vérifié) :
  matrice_autorisation.py gabarit  [--sortie security/06-dynamique/matrice.yaml]
  matrice_autorisation.py executer security/06-dynamique/matrice.yaml [--publishable <clé>] [--lecture-seule]
  matrice_autorisation.py executer ... --cible staging --g3 "<décision de PA, date>" --hote <hôte-staging>

Principe : on ne fait pas confiance à l'interface. Chaque identité de security/labo/identites.md tente, avec son JWT
(ou la seule clé publishable pour « anon »), de lire, créer, modifier, déplacer et supprimer sur SON tenant et sur
L'AUTRE. Une fuite est prouvée par un marqueur SECRET-TENANT-<autre>-nnn dans une réponse.

Garde-fous :
- Par défaut la cible doit être locale (127.0.0.1 / localhost). Sinon arrêt.
- « --cible staging » exige --g3 (décision de PA citée) et --hote, et force --lecture-seule : aucune écriture hors labo.
- Les écritures (créer, modifier, déplacer, supprimer) ne visent que des lignes de test marquées. Remettre le labo
  à zéro après (labo.sh reset).
- Les jetons et clés sont caviardés dans les sorties.
Sorties : security/06-dynamique/matrice-resultats.md et matrice-resultats.json.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import subprocess

import yaml

NS = uuid.UUID("6f1c3c1e-3b7a-4c55-9d0e-6c1a5b0e0a11")  # identique à appsec-labo/labo_init.py
ECRITURES = ("creer", "modifier", "deplacer", "supprimer")

GABARIT = """# Matrice d'autorisation (format appsec-tests-dynamiques). A ADAPTER au schéma et aux règles métier.
# attendu : actions permises à chaque rôle SUR SON PROPRE TENANT. Sur l'autre tenant, tout doit être refusé.
# Actions : lire, creer, modifier, deplacer (changer la colonne de tenant), supprimer ; rpc : appeler ; storage : lire, lister
cible: labo
ressources:
  - id: accidents
    type: table
    nom: accidents
    colonne_marqueur: description        # colonne qui porte SECRET-TENANT-X-nnn
    colonne_tenant: entreprise_id
    ligne_exemple: {victime: "Personne fictive", gravite: 1}   # colonnes obligatoires pour un INSERT de test
    actions: [lire, creer, modifier, deplacer, supprimer]
    attendu:
      admin: [lire, creer, modifier, supprimer]
      membre: [lire, creer]
      lecteur: [lire]
      anon: []
  - id: stats
    type: rpc
    nom: stats_entreprise
    parametre_tenant: p_entreprise       # paramètre qui reçoit l'id de tenant
    actions: [appeler]
    attendu: {admin: [appeler], membre: [appeler], lecteur: [appeler], anon: []}
  - id: photos
    type: storage
    bucket: photos-accidents
    actions: [lister, lire]
    attendu: {admin: [lister, lire], membre: [lister, lire], lecteur: [lire], anon: []}
"""


def lab_uuid(*p):
    return str(uuid.uuid5(NS, "/".join(p)))


def cav(s):
    s = str(s)
    s = re.sub(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "eyJ…[jeton caviardé]", s)
    return re.sub(r"sb_(secret|publishable)_[A-Za-z0-9_\-]{6,}", r"sb_\1_…[caviardé]", s)


def req(methode, url, cle, jwt=None, corps=None, prefer=None):
    h = {"apikey": cle, "Content-Type": "application/json", "Authorization": "Bearer " + (jwt or cle)}
    if prefer:
        h["Prefer"] = prefer
    data = json.dumps(corps).encode() if corps is not None else None
    r = urllib.request.Request(url, data=data, headers=h, method=methode)
    try:
        with urllib.request.urlopen(r, timeout=20) as x:
            return x.status, x.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def lire_env(p):
    return dict(re.findall(r"^([A-Z_]+)=(.*)$", open(p, encoding="utf-8").read(), re.M)) if os.path.exists(p) else {}


def identites(p):
    ids, marq = [], {}
    for l in open(p, encoding="utf-8"):
        m = re.match(r"\|\s*([a-z0-9]+-[a-z0-9_]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(\S+@\S+)\s*\|", l)
        if m:
            ids.append({"id": m.group(1), "tenant": m.group(2), "role": m.group(3), "email": m.group(4)})
        m = re.match(r"\|\s*([\w.:\-]+)\s*\|\s*([A-Za-z0-9]+)\s*\|\s*`(SECRET-TENANT-[^`]+)`\s*\|", l)
        if m:
            marq.setdefault(m.group(1).split(".")[-1].replace("storage:", "storage:"), []).append((m.group(2), m.group(3)))
    return ids, marq


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = ap.add_subparsers(dest="cmd", required=True)
    g = s.add_parser("gabarit")
    g.add_argument("--sortie", default="security/06-dynamique/matrice.yaml")
    e = s.add_parser("executer")
    e.add_argument("matrice")
    e.add_argument("--env", default="security/labo/.env.lab")
    e.add_argument("--identites", default="security/labo/identites.md")
    e.add_argument("--publishable")
    e.add_argument("--lecture-seule", action="store_true")
    e.add_argument("--cible", choices=["labo", "staging"], default="labo")
    e.add_argument("--g3")
    e.add_argument("--hote")
    e.add_argument("--sortie", default="security/06-dynamique")
    a = ap.parse_args()

    if a.cmd == "gabarit":
        os.makedirs(os.path.dirname(a.sortie) or ".", exist_ok=True)
        if os.path.exists(a.sortie):
            sys.exit(f"{a.sortie} existe déjà")
        open(a.sortie, "w", encoding="utf-8").write(GABARIT)
        print(f"Gabarit écrit : {a.sortie}. L'adapter aux tables, RPC, buckets et règles métier réels.")
        return

    env = lire_env(a.env)
    url = env.get("SUPABASE_URL", "").rstrip("/")
    hote = urllib.parse.urlparse(url).hostname
    if a.cible == "labo" and hote not in ("127.0.0.1", "localhost"):
        sys.exit(f"ARRÊT : cible non locale ({url!r}). Hors labo, utiliser --cible staging avec la porte G3.")
    if a.cible == "staging":
        if not a.g3 or not a.hote:
            sys.exit("ARRÊT : --cible staging exige --g3 \"<décision de PA>\" et --hote <hôte autorisé>.")
        if hote != a.hote:
            sys.exit(f"ARRÊT : l'URL ({hote}) ne correspond pas à l'hôte autorisé ({a.hote}).")
        a.lecture_seule = True
        print("Staging : lecture seule forcée (aucune écriture hors labo).")

    cfg = yaml.safe_load(open(a.matrice, encoding="utf-8"))
    ids, marqueurs = identites(a.identites)
    app = env.get("LABO_APP", "")
    mdp = env.get("LABO_MOT_DE_PASSE", "")
    cle = a.publishable or os.environ.get("SUPABASE_PUBLISHABLE_KEY")
    if not cle:
        try:
            st = subprocess.run(["supabase", "status", "-o", "env"], capture_output=True, text=True, timeout=60).stdout
            stv = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', st, re.M))
            cle = stv.get("PUBLISHABLE_KEY") or stv.get("ANON_KEY")
        except Exception:
            pass
    if not cle:
        sys.exit("Clé publishable locale introuvable (--publishable ou supabase status).")
    tenants = sorted({i["tenant"] for i in ids})
    if len(tenants) < 2:
        sys.exit("Il faut au moins deux tenants dans identites.md pour tester l'isolation.")
    tid = {t: lab_uuid(app, "tenant", t) for t in tenants}

    sessions = [{"id": "anon", "tenant": None, "role": "anon", "jwt": None}]
    for i in ids:
        c, b = req("POST", f"{url}/auth/v1/token?grant_type=password", cle, corps={"email": i["email"], "password": mdp})
        jwt = json.loads(b).get("access_token") if c == 200 else None
        if not jwt:
            print(f"ÉCHEC connexion {i['id']} ({c}) : identité ignorée")
            continue
        sessions.append({**i, "jwt": jwt})

    resultats = []
    n = 0

    def noter(s_, r_, action, portee, statut, constat, requete, code, corps):
        nonlocal n
        n += 1
        resultats.append({"preuve": f"P-{n:03d}", "identite": s_["id"], "role": s_["role"], "ressource": r_["id"],
                          "action": action, "portee": portee, "statut": statut, "constat": constat,
                          "requete": cav(requete), "code": code, "extrait": cav(corps)[:300]})

    def autre(t):
        return next(x for x in tenants if x != t) if t else tenants[0]

    ORDRE = {"lire": 0, "lister": 0, "appeler": 0, "creer": 1, "modifier": 2, "deplacer": 3, "supprimer": 4}
    res = cfg.get("ressources", [])
    taches = sorted(((ORDRE.get(act, 0), ri, si, act) for ri, r in enumerate(res) for si, _ in enumerate(sessions)
                     for act in r.get("actions", [])), key=lambda x: (x[0], x[1], x[2]))
    for _, ri, si, action in taches:
        r, s_ = res[ri], sessions[si]
        att = r.get("attendu", {})
        permis = set(att.get(s_["role"], []))
        propre = s_["tenant"]
        cible_t = autre(propre)
        if action in ECRITURES and a.lecture_seule:
            noter(s_, r, action, "autre", "non exécuté", "lecture seule", "", 0, "")
            continue
        if r["type"] == "table":
            t = urllib.parse.quote(r["nom"])
            col, ten = r["colonne_marqueur"], r["colonne_tenant"]
            m_autre = [m for (tt, m) in marqueurs.get(r["nom"], []) if tt == cible_t]
            m_propre = [m for (tt, m) in marqueurs.get(r["nom"], []) if tt == propre]
            if action == "lire":
                q = f"{url}/rest/v1/{t}?select={col},{ten}"
                c, b = req("GET", q, cle, s_["jwt"])
                fuite = [m for m in m_autre if m in b]
                noter(s_, r, action, "autre", "ÉCHEC" if fuite else "OK",
                      f"marqueurs de {cible_t} visibles : {', '.join(fuite)}" if fuite else f"aucun marqueur de {cible_t}",
                      f"GET /rest/v1/{r['nom']}?select={col},{ten}", c, b)
                if propre:
                    vu = any(m in b for m in m_propre)
                    ok = vu == ("lire" in permis)
                    noter(s_, r, action, "propre", "OK" if ok else ("ÉCHEC" if vu else "écart"),
                          ("lecture permise" if vu else "lecture refusée") + (" (attendu)" if ok else " (non conforme à attendu)"),
                          f"GET /rest/v1/{r['nom']}", c, b)
            elif action == "creer":
                for portee, tt in (("autre", cible_t), ("propre", propre)):
                    if tt is None:
                        continue
                    ligne = {**(r.get("ligne_exemple") or {}), ten: tid[tt], col: f"TEST-ECRITURE-{s_['id']}-{portee}"}
                    c, b = req("POST", f"{url}/rest/v1/{t}", cle, s_["jwt"], [ligne], "return=representation")
                    cree = c in (200, 201) and "TEST-ECRITURE" in b
                    attendu_ok = (portee == "propre" and "creer" in permis)
                    statut = "OK" if cree == attendu_ok else ("ÉCHEC" if cree else "écart")
                    noter(s_, r, action, portee, statut, ("insertion acceptée" if cree else "insertion refusée") + f" ({c})",
                          f"POST /rest/v1/{r['nom']} {ten}={tt}", c, b)
            elif action in ("modifier", "supprimer"):
                for portee, ms in (("autre", m_autre), ("propre", m_propre)):
                    if not ms or (portee == "propre" and propre is None):
                        continue
                    m = ms[-1]
                    q = f"{url}/rest/v1/{t}?{col}=eq.{urllib.parse.quote(m)}"
                    if action == "modifier":
                        c, b = req("PATCH", q, cle, s_["jwt"], {col: m}, "return=representation")
                    else:
                        if portee == "propre" and "supprimer" not in permis:
                            pass
                        c, b = req("DELETE", q, cle, s_["jwt"], None, "return=representation")
                    fait = c in (200, 204) and m in b
                    attendu_ok = portee == "propre" and action in permis
                    statut = "OK" if fait == attendu_ok else ("ÉCHEC" if fait else "écart")
                    noter(s_, r, action, portee, statut, ("action acceptée" if fait else "action refusée") + f" sur {m} ({c})",
                          f"{'PATCH' if action == 'modifier' else 'DELETE'} /rest/v1/{r['nom']}?{col}=eq.{m}", c, b)
            elif action == "deplacer" and propre and m_propre:
                m = m_propre[0]
                q = f"{url}/rest/v1/{t}?{col}=eq.{urllib.parse.quote(m)}"
                c, b = req("PATCH", q, cle, s_["jwt"], {ten: tid[cible_t]}, "return=representation")
                fait = c == 200 and tid[cible_t] in b
                noter(s_, r, action, "propre→autre", "ÉCHEC" if fait else "OK",
                      (f"ligne {m} déplacée vers {cible_t} (V-DB-04)" if fait else "déplacement refusé") + f" ({c})",
                      f"PATCH /rest/v1/{r['nom']} set {ten}={cible_t}", c, b)
        elif r["type"] == "rpc":
            p = r.get("parametre_tenant")
            for portee, tt in (("autre", cible_t), ("propre", propre)):
                if tt is None and portee == "propre":
                    continue
                corps = {p: tid[tt]} if p else {}
                c, b = req("POST", f"{url}/rest/v1/rpc/{urllib.parse.quote(r['nom'])}", cle, s_["jwt"], corps)
                repond = c == 200 and b.strip() not in ("", "null", "[]", "{}")
                fuite = [m for (t2, m) in sum(marqueurs.values(), []) if t2 == cible_t and m in b]
                if portee == "autre":
                    statut = "ÉCHEC" if (repond and (fuite or s_["role"] == "anon" or p)) else "OK"
                    constat = (f"réponse pour le tenant {cible_t}" + (f", marqueurs {fuite}" if fuite else " (données d'un autre tenant ?)")) if repond else f"refusé ou vide ({c})"
                else:
                    ok = repond == ("appeler" in permis)
                    statut = "OK" if ok else ("ÉCHEC" if repond else "écart")
                    constat = ("réponse" if repond else "refus") + (" (attendu)" if ok else " (non conforme)")
                noter(s_, r, "appeler", portee, statut, constat, f"POST /rest/v1/rpc/{r['nom']} {p}={tt}", c, b)
        elif r["type"] == "storage":
            bk = r["bucket"]
            fich = [(tt, m) for (tt, m) in marqueurs.get(f"storage:{bk}", [])]
            if action == "lister":
                c, b = req("POST", f"{url}/storage/v1/object/list/{urllib.parse.quote(bk)}", cle, s_["jwt"],
                           {"prefix": tid[cible_t], "limit": 100})
                fuite = [m for (tt, m) in fich if tt == cible_t and m in b]
                noter(s_, r, action, "autre", "ÉCHEC" if fuite else "OK",
                      f"fichiers de {cible_t} listés : {fuite}" if fuite else "rien listé", f"POST /storage/v1/object/list/{bk} prefix={cible_t}", c, b)
            if action == "lire":
                for (tt, m) in fich:
                    if tt != cible_t:
                        continue
                    chemin = f"{tid[tt]}/{m}.txt"
                    c, b = req("GET", f"{url}/storage/v1/object/authenticated/{urllib.parse.quote(bk)}/{urllib.parse.quote(chemin)}", cle, s_["jwt"])
                    c2, b2 = req("GET", f"{url}/storage/v1/object/public/{urllib.parse.quote(bk)}/{urllib.parse.quote(chemin)}", cle)
                    lu = (c == 200 and m in b) or (c2 == 200 and m in b2)
                    noter(s_, r, action, "autre", "ÉCHEC" if lu else "OK",
                          (f"fichier {m} lisible" + (" par URL publique" if c2 == 200 and m in b2 else "")) if lu else "lecture refusée",
                          f"GET /storage/v1/object/(authenticated|public)/{bk}/{chemin}", c if c == 200 else c2, b if c == 200 else b2)

    os.makedirs(a.sortie, exist_ok=True)
    json.dump({"date": dt.datetime.now().isoformat(timespec="seconds"), "cible": a.cible, "resultats": resultats},
              open(os.path.join(a.sortie, "matrice-resultats.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    ech = [x for x in resultats if x["statut"] == "ÉCHEC"]
    ecarts = [x for x in resultats if x["statut"] == "écart"]
    L = [f"# Matrice d'autorisation : résultats ({a.cible}, {dt.date.today().isoformat()})", "",
         f"**{len(ech)} échecs de sécurité**, {len(ecarts)} écarts fonctionnels, {sum(1 for x in resultats if x['statut'] == 'OK')} contrôles conformes, "
         f"{sum(1 for x in resultats if x['statut'] == 'non exécuté')} non exécutés.", "",
         "Légende : ÉCHEC = accès qui aurait dû être refusé (faille). écart = refus d'une action attendue (fonctionnel, à vérifier). OK = conforme.", "",
         "| Preuve | Identité | Ressource | Action | Portée | Statut | Constat |", "|---|---|---|---|---|---|---|"]
    ordre = {"ÉCHEC": 0, "écart": 1, "non exécuté": 2, "OK": 3}
    for x in sorted(resultats, key=lambda x: (ordre[x["statut"]], x["ressource"], x["identite"])):
        L.append(f"| {x['preuve']} | {x['identite']} | {x['ressource']} | {x['action']} | {x['portee']} | {x['statut']} | {x['constat']} |")
    L += ["", "Requêtes et extraits de réponses (jetons caviardés) : `matrice-resultats.json`. "
          "Remettre le labo à zéro après ce test (écritures de test) : `security/labo/labo.sh reset`."]
    open(os.path.join(a.sortie, "matrice-resultats.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"{len(ech)} ÉCHEC, {len(ecarts)} écarts, {len(resultats)} contrôles. Écrit : {a.sortie}/matrice-resultats.md")
    sys.exit(1 if ech else 0)


if __name__ == "__main__":
    main()
