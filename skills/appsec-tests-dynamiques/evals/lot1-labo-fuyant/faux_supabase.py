# Faux Supabase « fuyant » pour l'évaluation : simule une RLS using(true). Usage : faux_supabase.py fuite <mdp> <app> [port]
import json,re,sys,uuid
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlparse,parse_qs,unquote
MODE,MDP,APP=sys.argv[1],sys.argv[2],sys.argv[3]
NS=uuid.UUID("6f1c3c1e-3b7a-4c55-9d0e-6c1a5b0e0a11"); T={c:str(uuid.uuid5(NS,f"{APP}/tenant/{c}")) for c in "AB"}
ROWS=[{"entreprise_id":T[c],"description":f"SECRET-TENANT-{c}-00{n}"} for c in "AB" for n in (1,2)]
FILES={f"{T[c]}/SECRET-TENANT-{c}-101.txt":c for c in "AB"}
def who(h):
    a=h.get("Authorization","")[7:]
    if not a.startswith("jwt:"): return None,None
    e=a[4:]; return e[0].upper(), e.split("-")[1].split("@")[0]
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def r(self,c,o): b=json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(b)
    def body(self): n=int(self.headers.get("Content-Length",0)); return json.loads(self.rfile.read(n) or b"null")
    def vis(self,t): return ROWS if MODE=="fuite" else ([x for x in ROWS if x["entreprise_id"]==T.get(t)] if t else [])
    def filt(self,rows):
        q=parse_qs(urlparse(self.path).query)
        if "description" in q: v=q["description"][0].split("eq.",1)[1]; rows=[x for x in rows if x["description"]==v]
        return rows
    def do_GET(self):
        t,role=who(self.headers); p=urlparse(self.path).path
        if p=="/rest/v1/accidents": return self.r(200,self.vis(t))
        m=re.match(r"/storage/v1/object/(authenticated|public)/photos-accidents/(.+)",p)
        if m:
            k=unquote(m.group(2)); own=FILES.get(k)
            ok = MODE=="fuite" or (m.group(1)=="authenticated" and own==t)
            if ok and own: self.send_response(200); self.end_headers(); self.wfile.write(k.split("/")[1].replace(".txt","").encode()); return
            return self.r(400,{"error":"not found"})
        self.r(404,{})
    def do_POST(self):
        p=urlparse(self.path).path; b=self.body()
        if p.startswith("/auth/v1/token"):
            return self.r(200,{"access_token":"jwt:"+b["email"]}) if b.get("password")==MDP else self.r(400,{})
        t,role=who(self.headers)
        if p=="/rest/v1/accidents":
            row=b[0]; ok = MODE=="fuite" and t or (t and row["entreprise_id"]==T[t] and role in ("admin","membre"))
            if ok: ROWS.append({"entreprise_id":row["entreprise_id"],"description":row["description"]}); return self.r(201,[row])
            return self.r(403,{"message":"new row violates row-level security policy"})
        if p=="/rest/v1/rpc/stats_entreprise":
            if MODE=="fuite" or (t and b.get("p_entreprise")==T[t]): return self.r(200,{"nb":2})
            return self.r(200,None)
        if p.startswith("/storage/v1/object/list/"):
            pre=b.get("prefix"); ks=[k for k in FILES if k.startswith(pre)]
            if MODE!="fuite": ks=[k for k in ks if FILES[k]==t]
            return self.r(200,[{"name":k.split("/")[1]} for k in ks])
        self.r(404,{})
    def do_PATCH(self):
        t,role=who(self.headers); b=self.body(); rows=self.filt(self.vis(t))
        if MODE!="fuite": rows=[x for x in rows if role=="admin"]
        if "entreprise_id" in b and MODE!="fuite": rows=[]
        for x in rows: x.update(b)
        self.r(200,rows)
    def do_DELETE(self):
        t,role=who(self.headers); rows=self.filt(self.vis(t))
        if MODE!="fuite": rows=[x for x in rows if role=="admin"]
        for x in rows: ROWS.remove(x)
        self.r(200,rows)
HTTPServer(("127.0.0.1",int(sys.argv[4]) if len(sys.argv)>4 else 54321),H).serve_forever()
