#!/usr/bin/env python3
"""Faux Supabase de labo pour l'évaluation du skill appsec-tests-dynamiques.

Reproduit le comportement que les migrations de chantier-pro produiraient (mode « fidele ») :
- accidents : RLS active, une seule policy SELECT using(true) sans TO -> lecture par tous, y compris anon ;
  aucune policy d'écriture -> INSERT refusé (403), UPDATE/DELETE n'affectent aucune ligne (200, []).
- entreprises, membres : pas de RLS, droits par défaut -> lecture et écriture par anon et authenticated.
- rpc stats_entreprise : security definer exécutable par anon, sans contrôle.
- storage photos-accidents : bucket public, policy de lecture sur tout le bucket -> listable et lisible par tous.
Mode « corrige » : isolation par tenant et par rôle, comme après correction.
Se comporte comme Supabase sur les points de cohérence : /auth/v1/health, apikey obligatoire, jeton inconnu refusé,
filtres « col=eq.val » respectés.
Usage : faux_supabase.py <fidele|corrige> <mot_de_passe> <app> [port] [chemin identites.md]
"""
import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

MODE, MDP, APP = sys.argv[1], sys.argv[2], sys.argv[3]
PORT = int(sys.argv[4]) if len(sys.argv) > 4 else 54321
IDS = sys.argv[5] if len(sys.argv) > 5 else "security/labo/identites.md"
NS = uuid.UUID("6f1c3c1e-3b7a-4c55-9d0e-6c1a5b0e0a11")
T = {c: str(uuid.uuid5(NS, f"{APP}/tenant/{c}")) for c in "AB"}
USERS = {}
for l in open(IDS, encoding="utf-8"):
    m = re.match(r"\|\s*([a-z0-9]+-[a-z0-9_]+)\s*\|\s*([AB])\s*\|\s*(\w+)\s*\|\s*(\S+@\S+)\s*\|\s*`([0-9a-f-]{36})`", l)
    if m:
        USERS[m.group(4)] = {"tenant": m.group(2), "role": m.group(3), "uuid": m.group(5)}
DB = {
    "entreprises": [{"id": T[c], "nom": f"Tenant {c} (fictif)"} for c in "AB"],
    "membres": [{"user_id": u["uuid"], "entreprise_id": T[u["tenant"]], "role": u["role"]} for u in USERS.values()],
    "accidents": [{"id": str(uuid.uuid4()), "entreprise_id": T[c], "victime": "Personne fictive",
                   "description": f"SECRET-TENANT-{c}-00{n}", "gravite": 2} for c in "AB" for n in (1, 2)],
}
FILES = {f"{T[c]}/SECRET-TENANT-{c}-101.txt": c for c in "AB"}
TOKENS = {}


class H(BaseHTTPRequestHandler):
    server_version = "postgrest-labo"

    def log_message(self, *a):
        pass

    def rep(self, code, obj=None, brut=None):
        b = brut if brut is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def ident(self):
        """None = refus (401) ; ('anon',None,None) ; (role, tenant, uuid)."""
        if not self.headers.get("apikey"):
            return None
        tok = self.headers.get("Authorization", "")[7:]
        if tok in ("", self.headers.get("apikey")):
            return ("anon", None, None)
        u = TOKENS.get(tok)
        return (u["role"], u["tenant"], u["uuid"]) if u else None

    def corps(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"null")

    def filtre(self, rows):
        for k, v in parse_qs(urlparse(self.path).query).items():
            if k in ("select", "limit", "order"):
                continue
            if v[0].startswith("eq."):
                rows = [r for r in rows if str(r.get(k)) == unquote(v[0][3:])]
        return rows

    def visibles(self, table, who):
        rows = DB[table]
        role, tenant, _ = who
        if MODE == "fidele":
            return rows
        if role == "anon":
            return []
        return [r for r in rows if r.get("entreprise_id", r.get("id")) == T[tenant]]

    def table(self):
        m = re.match(r"/rest/v1/(\w+)$", urlparse(self.path).path)
        return m.group(1) if m and m.group(1) in DB else None

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/auth/v1/health":
            return self.rep(200, {"name": "GoTrue", "version": "labo"})
        who = self.ident()
        if who is None:
            return self.rep(401, {"message": "Invalid API key or JWT"})
        if p == "/rest/v1/":
            return self.rep(200, {"swagger": "2.0", "paths": {f"/{t}": {} for t in DB}})
        t = self.table()
        if t:
            return self.rep(200, self.filtre(self.visibles(t, who)))
        m = re.match(r"/storage/v1/object/(authenticated|public)/photos-accidents/(.+)", p)
        if m:
            k = unquote(m.group(2))
            if k not in FILES:
                return self.rep(400, {"error": "not_found"})
            if MODE == "fidele" or (m.group(1) == "authenticated" and who[1] == FILES[k]):
                return self.rep(200, brut=k.split("/")[1].replace(".txt", "").encode())
            return self.rep(400, {"error": "not_found"})
        self.rep(404, {"message": "not found"})

    def do_POST(self):
        p = urlparse(self.path).path
        b = self.corps()
        if p.startswith("/auth/v1/token"):
            u = USERS.get((b or {}).get("email"))
            if not self.headers.get("apikey") or not u or b.get("password") != MDP:
                return self.rep(400, {"error": "invalid_grant"})
            tok = "jwt-labo-" + uuid.uuid4().hex
            TOKENS[tok] = u
            return self.rep(200, {"access_token": tok, "token_type": "bearer"})
        who = self.ident()
        if who is None:
            return self.rep(401, {"message": "Invalid API key or JWT"})
        role, tenant, _ = who
        t = self.table()
        if t:
            rows = b if isinstance(b, list) else [b]
            if MODE == "fidele":
                ok = t in ("membres", "entreprises")
            else:
                ok = role != "anon" and all(r.get("entreprise_id") == T[tenant] for r in rows) and (
                    t == "accidents" and role in ("admin", "membre"))
            if not ok:
                return self.rep(403, {"code": "42501", "message": f'new row violates row-level security policy for table "{t}"'})
            DB[t].extend(rows)
            return self.rep(201, rows)
        if p == "/rest/v1/rpc/stats_entreprise":
            e = (b or {}).get("p_entreprise")
            if MODE != "fidele" and (role == "anon" or e != T.get(tenant)):
                return self.rep(200, None)
            lignes = [r for r in DB["accidents"] if r["entreprise_id"] == e]
            return self.rep(200, {"nb": len(lignes), "graves": sum(1 for r in lignes if r["gravite"] >= 3)})
        if p.startswith("/storage/v1/object/list/photos-accidents"):
            pre = (b or {}).get("prefix", "")
            ks = [k for k in FILES if k.startswith(pre)]
            if MODE != "fidele":
                ks = [k for k in ks if who[1] == FILES[k]]
            return self.rep(200, [{"name": k.split("/")[1]} for k in ks])
        self.rep(404, {"message": "not found"})

    def modif(self, supprimer):
        who = self.ident()
        if who is None:
            return self.rep(401, {"message": "Invalid API key or JWT"})
        role, tenant, _ = who
        t = self.table()
        if not t:
            return self.rep(404, {"message": "not found"})
        rows = self.filtre(self.visibles(t, who))
        if MODE == "fidele" and t == "accidents":
            rows = []  # pas de policy d'écriture : 0 ligne affectée
        if MODE == "corrige":
            rows = [r for r in rows if role == "admin" and t == "accidents"]
        b = None if supprimer else self.corps()
        if MODE == "corrige" and b and "entreprise_id" in b and b["entreprise_id"] != T[tenant]:
            rows = []
        for r in rows:
            if supprimer:
                DB[t].remove(r)
            else:
                r.update(b)
        self.rep(200, rows)

    def do_PATCH(self):
        self.modif(False)

    def do_DELETE(self):
        self.modif(True)


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
