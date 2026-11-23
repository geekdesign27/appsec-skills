#!/usr/bin/env python3
"""Revue statique des migrations Supabase : RLS, policies, vues, fonctions, droits, Storage, Realtime.

Usage :
  revue_sql.py <dossier supabase/migrations> [--json] [--sortie security/05-statique/revue-sql.md]

Lit les migrations dans l'ordre et reconstruit l'état final (une policy supprimée puis recréée compte une fois).
Produit un tableau par table et une liste de signaux reliés au catalogue partagé (V-DB-xx, V-AUTH-xx).
Analyse par motifs : elle repère des signaux, elle ne prouve pas une faille. Statut de chaque signal :
  « constaté » = le code le montre tel quel ; l'exploitabilité reste à confirmer en phase 6.
Limites : SQL dynamique, policies créées hors migrations (Dashboard) et fonctions plpgsql complexes
ne sont pas interprétés. Les compléter avec « supabase db advisors --type security » et une lecture humaine.
"""
import argparse
import glob
import json
import os
import re
import sys

FLAGS = re.I | re.S


def strip_comments(sql):
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


def split_statements(sql):
    """Découpe en instructions en respectant les blocs $$...$$ et les chaînes."""
    out, buf, i, n = [], [], 0, len(sql)
    dollar = None
    quote = False
    while i < n:
        c = sql[i]
        if dollar:
            if sql.startswith(dollar, i):
                buf.append(dollar)
                i += len(dollar)
                dollar = None
                continue
        elif quote:
            if c == "'":
                quote = False
        else:
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                dollar = m.group(0)
                buf.append(dollar)
                i += len(dollar)
                continue
            if c == "'":
                quote = True
            elif c == ";":
                out.append("".join(buf).strip())
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return out


def nom(x):
    x = x.strip().strip('"').lower()
    x = x.replace('"', "")
    return x if "." in x else "public." + x


def analyser(dossier):
    tables, policies, vues, fonctions, grants, buckets, realtime = {}, {}, {}, {}, [], {}, set()
    fichiers = sorted(glob.glob(os.path.join(dossier, "*.sql")))
    for f in fichiers:
        for st in split_statements(strip_comments(open(f, encoding="utf-8").read())):
            s = " ".join(st.split())
            src = os.path.basename(f)
            m = re.match(r"create table (?:if not exists )?([\w.\"]+)\s*\((.*)\)", s, FLAGS)
            if m:
                t = nom(m.group(1))
                cols = [c.strip().split()[0].strip('"').lower() for c in re.split(r",(?![^()]*\))", m.group(2)) if c.strip()]
                tables[t] = {"rls": False, "force": False, "colonnes": cols, "source": src}
                continue
            m = re.match(r"alter table (?:only )?([\w.\"]+) (enable|disable|force|no force) row level security", s, FLAGS)
            if m:
                t = nom(m.group(1))
                tables.setdefault(t, {"rls": False, "force": False, "colonnes": [], "source": src})
                act = m.group(2).lower()
                if act == "enable":
                    tables[t]["rls"] = True
                elif act == "disable":
                    tables[t]["rls"] = False
                elif act == "force":
                    tables[t]["force"] = True
                continue
            m = re.match(r"drop policy (?:if exists )?\"?([^\"]+?)\"? on ([\w.\"]+)", s, FLAGS)
            if m:
                policies.pop((nom(m.group(2)), m.group(1).lower()), None)
                continue
            m = re.match(r"create policy \"?([^\"]+?)\"? on ([\w.\"]+)(.*)", s, FLAGS)
            if m:
                pname, t, rest = m.group(1).lower(), nom(m.group(2)), m.group(3)
                cmd = (re.search(r"\bfor (all|select|insert|update|delete)\b", rest, FLAGS) or [None, "all"])[1].lower()
                roles = (re.search(r"\bto ([\w, \"]+?)(?= using| with check|$)", rest, FLAGS) or [None, "public"])[1]
                using = re.search(r"\busing\s*\((.*?)\)\s*(?:with check|$)", rest, FLAGS)
                check = re.search(r"\bwith check\s*\((.*)\)\s*$", rest, FLAGS)
                perm = "restrictive" if re.search(r"as restrictive", rest, FLAGS) else "permissive"
                policies[(t, pname)] = {"table": t, "nom": pname, "commande": cmd, "roles": roles.strip().lower(),
                                        "using": using.group(1).strip() if using else None,
                                        "with_check": check.group(1).strip() if check else None,
                                        "mode": perm, "source": src}
                continue
            m = re.match(r"create (?:or replace )?view ([\w.\"]+)(.*?)\bas\b", s, FLAGS)
            if m:
                vues[nom(m.group(1))] = {"security_invoker": bool(re.search(r"security_invoker\s*=\s*(true|on)", m.group(2), FLAGS)), "source": src}
                continue
            m = re.match(r"alter view ([\w.\"]+) set \((.*)\)", s, FLAGS)
            if m and re.search(r"security_invoker\s*=\s*(true|on)", m.group(2), FLAGS):
                vues.setdefault(nom(m.group(1)), {"source": src})["security_invoker"] = True
                continue
            m = re.match(r"create (?:or replace )?function ([\w.\"]+)\s*\((.*?)\)(.*)", s, FLAGS)
            if m:
                fn = nom(m.group(1))
                corps = m.group(3)
                fonctions[fn] = {"definer": bool(re.search(r"security definer", corps, FLAGS)),
                                 "search_path": bool(re.search(r"set search_path", corps, FLAGS)),
                                 "args": m.group(2).strip(),
                                 "auth_uid": bool(re.search(r"auth\.uid\(\)|auth\.jwt\(\)", corps, FLAGS)),
                                 "source": src}
                continue
            m = re.match(r"grant (.+?) on (?:function |table )?([\w.\"]+)(?:\s*\([^)]*\))? to (.+)", s, FLAGS)
            if m:
                grants.append({"droits": m.group(1).lower(), "objet": nom(m.group(2)), "a": m.group(3).lower(), "source": src})
                continue
            m = re.search(r"insert into storage\.buckets\s*\(([^)]*)\)\s*values\s*\((.*)\)", s, FLAGS)
            if m:
                cols = [c.strip().lower() for c in m.group(1).split(",")]
                vals = [v.strip().strip("'").lower() for v in re.split(r",(?![^()]*\))", m.group(2))]
                d = dict(zip(cols, vals))
                buckets[d.get("id") or d.get("name")] = {"public": d.get("public") == "true", "source": src}
                continue
            m = re.match(r"alter publication supabase_realtime add table (.+)", s, FLAGS)
            if m:
                realtime.update(nom(x) for x in m.group(1).split(","))
    return fichiers, tables, policies, vues, fonctions, grants, buckets, realtime


DOSSIER = "."


def signaux(tables, policies, vues, fonctions, grants, buckets, realtime):
    S = []
    def add(cid, objet, constat, gravite):
        S.append({"catalogue": cid, "objet": objet, "constat": constat, "indication": gravite})
    exposees = {t: v for t, v in tables.items() if t.startswith("public.")}
    pol_par_table = {}
    for p in policies.values():
        pol_par_table.setdefault(p["table"], []).append(p)
    for t, v in exposees.items():
        if not v["rls"]:
            add("V-DB-01", t, "RLS non activée sur une table du schéma exposé", "élevée")
            continue
        ps = pol_par_table.get(t, [])
        if not ps:
            add("info", t, "RLS activée sans aucune policy : tout est refusé aux rôles applicatifs (vérifier que c'est voulu)", "info")
        cmds = {p["commande"] for p in ps}
        if ps and "all" not in cmds:
            manquantes = {"select", "insert", "update", "delete"} - cmds
            if manquantes:
                add("V-DB-03", t, f"pas de policy pour : {', '.join(sorted(manquantes))} (refusé par défaut, à confirmer comme voulu)", "info")
        if any(c in v["colonnes"] for c in ("role", "is_admin", "plan", "tenant_id", "entreprise_id", "organisation_id", "org_id")):
            upd = [p for p in ps if p["commande"] in ("update", "all")]
            if upd:
                add("V-DB-09", t, "colonne sensible (rôle, plan ou tenant) modifiable par une policy UPDATE/ALL : vérifier les privilèges de colonne", "moyenne")
    for p in policies.values():
        u = (p["using"] or "").replace(" ", "").lower()
        w = (p["with_check"] or "").replace(" ", "").lower()
        if u in ("true", "(true)") or w in ("true", "(true)"):
            add("V-DB-02", f'{p["table"]} / {p["nom"]}', f'policy {p["commande"].upper()} en « true » pour {p["roles"]}', "élevée")
        if p["roles"] in ("public", "anon") and p["commande"] != "select":
            add("V-DB-02", f'{p["table"]} / {p["nom"]}', f'policy d\'écriture ouverte au rôle {p["roles"]}', "élevée")
        elif p["roles"] == "public" and u not in ("true", "(true)"):
            add("V-DB-02", f'{p["table"]} / {p["nom"]}', "policy sans clause TO : s'applique aussi au rôle anon", "moyenne")
        if p["commande"] in ("update", "all") and not p["with_check"]:
            # Sans WITH CHECK, Postgres réapplique USING à la nouvelle ligne : le risque dépend de ce que USING contraint.
            contraint_tenant = re.search(r"tenant|entreprise|cabinet|org", u) is not None
            add("V-DB-04", f'{p["table"]} / {p["nom"]}',
                "UPDATE sans WITH CHECK explicite : Postgres réapplique USING à la nouvelle ligne ; "
                + ("USING contraint le tenant, vérifier les colonnes sensibles restées modifiables"
                   if contraint_tenant else "USING ne contraint pas le tenant : la ligne peut être déplacée vers un autre tenant si la colonne est modifiable"),
                "moyenne" if contraint_tenant else "élevée")
        if p["commande"] == "insert" and not p["with_check"]:
            add("V-DB-04", f'{p["table"]} / {p["nom"]}', "INSERT sans WITH CHECK : aucune condition sur la ligne insérée (à vérifier)", "élevée")
        if "user_metadata" in u + w:
            add("V-DB-06", f'{p["table"]} / {p["nom"]}', "policy basée sur user_metadata (modifiable par l'utilisateur)", "élevée")
        fonctions_sures = {f.split(".")[-1] for f, d in fonctions.items() if d["auth_uid"]}
        appelle_sure = any(re.search(r"\b%s\(" % re.escape(f), u) for f in fonctions_sures)
        if p["using"] and not appelle_sure and "auth.uid()" not in u and "auth.jwt()" not in u and u not in ("true", "(true)") and "select" not in u:
            add("V-DB-05", f'{p["table"]} / {p["nom"]}', "policy sans auth.uid() ni auth.jwt() : vérifier d'où vient le critère", "moyenne")
    for v, d in vues.items():
        if v.startswith("public.") and not d.get("security_invoker"):
            add("V-DB-07", v, "vue exposée sans security_invoker : elle s'exécute avec les droits de son créateur", "élevée")
    exec_anon = {g["objet"] for g in grants if "execute" in g["droits"] and re.search(r"\b(anon|public)\b", g["a"])}
    revoque_public = set()
    for f in glob.glob(os.path.join(DOSSIER, "*.sql")):
        for m in re.finditer(r"revoke\s+(?:all|execute)[^;]*?on\s+(?:function\s+)?([\w.\"]+)[^;]*?from\s+([^;]+)", strip_comments(open(f, encoding="utf-8").read()), FLAGS):
            if re.search(r"\b(public|anon)\b", m.group(2), re.I):
                revoque_public.add(nom(m.group(1)))
    exec_auth = {g["objet"] for g in grants if "execute" in g["droits"] and "authenticated" in g["a"]}
    for f, d in fonctions.items():
        if not f.startswith("public."):
            continue
        if d["definer"]:
            if not d["search_path"]:
                add("V-DB-08", f, "SECURITY DEFINER sans search_path fixé", "moyenne")
            if not d["auth_uid"]:
                if f in exec_anon:
                    qui = "anon (droit accordé explicitement)"
                elif f in revoque_public:
                    qui = "authenticated seulement (droit PUBLIC révoqué)" if f in exec_auth else "personne côté API (droit PUBLIC révoqué)"
                else:
                    qui = "PUBLIC par défaut, donc aussi anon : un GRANT à authenticated ne retire pas ce droit, il faut REVOKE ... FROM public, anon"
                add("V-DB-08", f, f"SECURITY DEFINER sans contrôle auth.uid()/auth.jwt(), exécutable par {qui}",
                    "info" if qui.startswith("personne") else "élevée")
    for g in grants:
        if g["objet"].startswith("public.") and re.search(r"\banon\b", g["a"]) and re.search(r"insert|update|delete|all", g["droits"]):
            add("V-DB-02", g["objet"], f'droits d\'écriture accordés à anon ({g["droits"]})', "élevée")
    for b, d in buckets.items():
        if d["public"]:
            add("V-DB-10", f"storage:{b}", "bucket public : tout objet est lisible par URL sans authentification", "élevée")
    for t in sorted(realtime):
        ps = [p for p in policies.values() if p["table"] == t and p["commande"] in ("select", "all")]
        if any((p["using"] or "").replace(" ", "").lower() in ("true", "(true)") for p in ps) or not tables.get(t, {}).get("rls", True):
            add("V-DB-11", t, "table publiée en Realtime avec une lecture ouverte : diffusion à tous les abonnés", "élevée")
        else:
            add("info", t, "table publiée en Realtime : vérifier le filtrage par tenant en phase 6", "info")
    return S


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dossier")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sortie")
    a = ap.parse_args()
    global DOSSIER
    DOSSIER = a.dossier
    fichiers, tables, policies, vues, fonctions, grants, buckets, realtime = analyser(a.dossier)
    S = signaux(tables, policies, vues, fonctions, grants, buckets, realtime)
    if a.json:
        print(json.dumps({"fichiers": [os.path.basename(f) for f in fichiers], "signaux": S,
                          "policies": list(policies.values())}, ensure_ascii=False, indent=2))
        return
    L = [f"# Revue statique des migrations ({len(fichiers)} fichiers)", "",
         "Analyse par motifs : chaque ligne est un signal **constaté dans le code**, à confirmer par un test en phase 6.", "",
         "## Tables du schéma public", "", "| Table | RLS | Policies (commande : rôles) |", "|---|---|---|"]
    for t, v in sorted(tables.items()):
        if not t.startswith("public."):
            continue
        ps = [f'{p["commande"]} : {p["roles"]}' for p in policies.values() if p["table"] == t]
        L.append(f'| {t} | {"oui" if v["rls"] else "**non**"} | {"; ".join(ps) or "aucune"} |')
    L += ["", f"## Signaux ({len(S)})", "", "| Catalogue | Objet | Constat | Indication |", "|---|---|---|---|"]
    ordre = {"élevée": 0, "moyenne": 1, "info": 2}
    for s in sorted(S, key=lambda x: (ordre.get(x["indication"], 3), x["catalogue"])):
        L.append(f'| {s["catalogue"]} | {s["objet"]} | {s["constat"]} | {s["indication"]} |')
    L += ["", "Limites : SQL dynamique, réglages faits dans le Dashboard et logique plpgsql non interprétés. "
          "Compléter par `supabase db advisors --type security` et une lecture humaine des policies."]
    txt = "\n".join(L) + "\n"
    if a.sortie:
        os.makedirs(os.path.dirname(a.sortie) or ".", exist_ok=True)
        open(a.sortie, "w", encoding="utf-8").write(txt)
        print(f"Écrit : {a.sortie} ({len(S)} signaux)")
    else:
        print(txt)


if __name__ == "__main__":
    main()
