import json,subprocess,sys,os
from concurrent.futures import ThreadPoolExecutor
ev=json.load(open(sys.argv[1])); skill=sys.argv[2]; runs=int(sys.argv[3]) if len(sys.argv)>3 else 1
env={k:v for k,v in os.environ.items() if k!="CLAUDECODE"}
def one(q):
    try: out=subprocess.run(["claude","-p",q,"--model","claude-opus-5-5","--output-format","stream-json","--verbose","--max-turns","1"],capture_output=True,text=True,timeout=150,cwd="/tmp",env=env).stdout
    except Exception: return None
    called=[]
    for l in out.splitlines():
        try: d=json.loads(l)
        except: continue
        if d.get("type")=="assistant":
            for c in d["message"].get("content",[]):
                if c.get("type")=="tool_use" and c["name"]=="Skill": called.append(c["input"].get("skill",""))
    return called
jobs=[(e,r) for e in ev for r in range(runs)]
with ThreadPoolExecutor(8) as ex: res=list(ex.map(lambda j: one(j[0]["query"]), jobs))
agg={}
for (e,_),c in zip(jobs,res):
    a=agg.setdefault(e["query"],{"should":e["should_trigger"],"hits":0,"n":0,"autres":set()})
    a["n"]+=1
    if c and any(s.endswith(skill) for s in c): a["hits"]+=1
    for s in (c or []):
        if not s.endswith(skill): a["autres"].add(s)
ok=0
for q,a in agg.items():
    rate=a["hits"]/a["n"]; p=(rate>=0.5)==a["should"]; ok+=p
    print(f"{'OK ' if p else 'KO '} attendu={'oui' if a['should'] else 'non'} taux={rate:.2f} autres={sorted(a['autres'])} | {q[:70]}")
print(f"Score : {ok}/{len(agg)}")
