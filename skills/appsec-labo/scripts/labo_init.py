#!/usr/bin/env python3
"""Génère le kit de laboratoire AppSec d'une app Supabase (profil, section 7).

Usage :
  labo_init.py gabarit <racine-app> [--tenants A,B] [--roles owner,admin,member,viewer]
      -> crée security/labo/identites.yaml (à adapter au schéma réel de l'app)
  labo_init.py generer <racine-app>
      -> lit security/labo/identites.yaml et écrit :
         supabase/seeds/90_labo_identites.sql   (comptes, tenants, appartenances, données marquées)
         security/labo/.env.lab                 (valeurs de test uniquement)
         security/labo/labo.sh                  (up | reset | verifier | down, avec garde-fous)
         security/labo/identites.md             (tableau lisible des identités)

Principes :
- Identifiants déterministes (uuid5) : après chaque remise à zéro, les mêmes comptes ont les mêmes UUID.
- Données synthétiques, avec un marqueur unique par tenant (SECRET-TENANT-B-001) pour prouver une fuite.
- Aucune valeur de production : le script refuse un identites.yaml qui contient une URL *.supabase.co
  ou une clé secrète.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import sys
import uuid

import yaml

NS = uuid.UUID("6f1c3c1e-3b7a-4c55-9d0e-6c1a5b0e0a11")  # espace de noms fixe des UUID du labo
ICI = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(os.path.dirname(ICI), "assets")
INTERDITS = [r"[a-z0-9]{20}\.supabase\.co", r"sb_secret_[A-Za-z0-9_-]{10,}", r"service_role"]

GABARIT = """# Identités du laboratoire AppSec : {app}
# A ADAPTER au schéma réel (voir security/01-inventaire.md). Valeurs de test uniquement.
# Placeholders disponibles dans les modèles SQL :
#   {{tenant_id}} {{tenant_code}} {{tenant_nom}} {{user_id}} {{email}} {{role}} {{marqueur}} {{n}}

app: {app}
domaine_email: labo.test          # domaine réservé, jamais routé
tenants:
{tenants}
roles: [{roles}]                  # rôles réels de l'app, du plus fort au plus faible
anonyme: true                     # identité « anon » : pas de compte, seulement la clé publishable

# Où l'app stocke le rôle et le tenant. Garder les modèles utiles, supprimer les autres.
modeles_sql:
  # Une ligne par tenant (table des organisations)
  tenant: >-
    insert into public.entreprises (id, nom) values ('{{tenant_id}}', '{{tenant_nom}}');
  # Une ligne par identité (table d'appartenance)
  membre: >-
    insert into public.membres (user_id, entreprise_id, role) values ('{{user_id}}', '{{tenant_id}}', '{{role}}');
  # Si le rôle ou le tenant vit dans le JWT (app_metadata), sinon laisser vide
app_metadata: {{}}                # ex. {{tenant_id: "{{tenant_id}}", role: "{{role}}"}}

# Données marquées : une série par tenant, pour prouver une fuite sans ambiguïté
donnees:
  - table: public.accidents
    par_tenant: 2
    modele: >-
      insert into public.accidents (entreprise_id, victime, description, gravite)
      values ('{{tenant_id}}', 'Personne fictive {{n}}', '{{marqueur}}', 2);

# Fichiers marqués dans le Storage local (déposés par labo_fichiers.py après chaque reset). Supprimer si inutile.
fichiers:
  - bucket: photos-accidents
    par_tenant: 1
    chemin: "{{tenant_id}}/{{marqueur}}.txt"
"""


def lab_uuid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


def sql_str(s):
    return str(s).replace("'", "''")


def remplir(modele, ctx):
    out = modele
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", sql_str(v))
    reste = re.findall(r"\{[a-z_]+\}", out)
    if reste:
        sys.exit(f"Placeholder inconnu dans un modèle SQL : {reste}")
    return out.strip()


def cmd_gabarit(a):
    racine = os.path.abspath(a.racine)
    d = os.path.join(racine, "security", "labo")
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "identites.yaml")
    if os.path.exists(f) and not a.forcer:
        sys.exit(f"{f} existe déjà (utiliser --forcer pour l'écraser)")
    app = a.app or os.path.basename(racine)
    tenants = "\n".join(f"  - {{code: {t}, nom: \"Tenant {t} (fictif)\"}}" for t in a.tenants.split(","))
    with open(f, "w", encoding="utf-8") as fh:
        fh.write(GABARIT.format(app=app, tenants=tenants, roles=", ".join(a.roles.split(","))))
    print(f"Gabarit écrit : {f}")
    print("Étape suivante : adapter modeles_sql et donnees au schéma réel, puis « labo_init.py generer ».")


def verifier_propre(texte, nom):
    for motif in INTERDITS:
        if re.search(motif, texte):
            sys.exit(f"Refus : {nom} contient une valeur qui ressemble à de la production ({motif}).")


def cmd_generer(a):
    racine = os.path.abspath(a.racine)
    lab = os.path.join(racine, "security", "labo")
    src = os.path.join(lab, "identites.yaml")
    brut = open(src, encoding="utf-8").read()
    verifier_propre(brut, "identites.yaml")
    cfg = yaml.safe_load(brut)
    app = cfg.get("app") or os.path.basename(racine)
    dom = cfg.get("domaine_email", "labo.test")
    roles = cfg["roles"]
    tenants = cfg["tenants"]
    mod = cfg.get("modeles_sql") or {}
    appmeta = cfg.get("app_metadata") or {}
    # Mot de passe de test stable : réutilisé s'il existe déjà, pour que le seed ne change pas à chaque génération
    mdp = None
    envp = os.path.join(lab, ".env.lab")
    if os.path.exists(envp):
        m = re.search(r"^LABO_MOT_DE_PASSE=(.+)$", open(envp, encoding="utf-8").read(), re.M)
        mdp = m.group(1).strip() if m else None
    mdp = mdp or "Labo-" + secrets.token_urlsafe(14)

    lignes = [
        "-- Seed du laboratoire AppSec (généré par appsec-labo/labo_init.py). NE PAS appliquer hors labo.",
        "-- Garde : refuse de s'exécuter sur une base qui contient déjà des comptes réels",
        "-- (tout e-mail hors du domaine de labo). Une base de labo fraîche n'a que des comptes de test.",
        "do $$ begin",
        f"  if exists (select 1 from auth.users where email not like '%@{dom}') then",
        "    raise exception 'Seed labo refusé : la base contient des comptes hors labo (base réelle ?)';",
        "  end if;",
        "end $$;",
        "",
        "-- 1. Comptes de test (mot de passe commun dans security/labo/.env.lab)",
    ]
    ident = []
    for t in tenants:
        code = str(t["code"])
        tid = lab_uuid(app, "tenant", code)
        tnom = t.get("nom", f"Tenant {code}")
        for r in roles:
            uid = lab_uuid(app, "user", code, r)
            email = f"{code.lower()}-{r}@{dom}"
            ctx = dict(tenant_id=tid, tenant_code=code, tenant_nom=tnom, user_id=uid, email=email, role=r)
            meta = {"provider": "email", "providers": ["email"]}
            for k, v in appmeta.items():
                meta[k] = remplir(str(v), ctx)
            meta_sql = sql_str(json.dumps(meta, ensure_ascii=False))
            lignes.append(
                "insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, "
                "raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, email_change, "
                "email_change_token_new, recovery_token) values ("
                f"'00000000-0000-0000-0000-000000000000', '{uid}', 'authenticated', 'authenticated', '{email}', "
                f"extensions.crypt('{mdp}', extensions.gen_salt('bf')), now(), "
                f"'{meta_sql}'::jsonb, '{{}}'::jsonb, now(), now(), '', '', '', '');")
            lignes.append(
                "insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, "
                f"created_at, updated_at) values ('{lab_uuid(app, 'identity', code, r)}', '{uid}', '{uid}', "
                f"jsonb_build_object('sub', '{uid}', 'email', '{email}'), 'email', now(), now(), now());")
            ident.append((f"{code.lower()}-{r}", code, r, email, uid))
    lignes += ["", "-- 2. Tenants et appartenances"]
    for t in tenants:
        code = str(t["code"])
        tid = lab_uuid(app, "tenant", code)
        ctx = dict(tenant_id=tid, tenant_code=code, tenant_nom=t.get("nom", f"Tenant {code}"))
        if mod.get("tenant"):
            lignes.append(remplir(mod["tenant"], ctx))
    if mod.get("membre"):
        for (_, code, r, email, uid) in ident:
            tid = lab_uuid(app, "tenant", code)
            lignes.append(remplir(mod["membre"], dict(tenant_id=tid, tenant_code=code, user_id=uid, email=email, role=r)))
    lignes += ["", "-- 3. Données marquées (preuve de fuite sans ambiguïté)"]
    marqueurs = []
    for d in cfg.get("donnees") or []:
        for t in tenants:
            code = str(t["code"])
            for n in range(1, int(d.get("par_tenant", 1)) + 1):
                mk = f"SECRET-TENANT-{code}-{len([m for m in marqueurs if m[1] == code]) + 1:03d}"
                marqueurs.append((d["table"], code, mk))
                lignes.append(remplir(d["modele"], dict(tenant_id=lab_uuid(app, "tenant", code), tenant_code=code,
                                                         marqueur=mk, n=n)))
    sql = "\n".join(lignes) + "\n"
    verifier_propre(sql, "le seed généré")

    seeds = os.path.join(racine, "supabase", "seeds")
    os.makedirs(seeds, exist_ok=True)
    with open(os.path.join(seeds, "90_labo_identites.sql"), "w", encoding="utf-8") as fh:
        fh.write(sql)

    env = [
        "# Laboratoire AppSec : valeurs de TEST uniquement. Ne jamais y copier une valeur de production.",
        "SUPABASE_URL=http://127.0.0.1:54321",
        "SUPABASE_DB_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres",
        f"LABO_MOT_DE_PASSE={mdp}",
        f"LABO_APP={app}",
        "# Clés locales : lues à chaque lancement dans « supabase status -o env », pas stockées ici.",
    ]
    with open(os.path.join(lab, ".env.lab"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(env) + "\n")
    shutil.copy(os.path.join(ASSETS, "labo.sh"), os.path.join(lab, "labo.sh"))
    os.chmod(os.path.join(lab, "labo.sh"), 0o755)
    for f in ("labo_verifier.py", "labo_fichiers.py"):
        shutil.copy(os.path.join(ICI, f), os.path.join(lab, f))

    md = [f"# Identités du laboratoire : {app}", "", "Mot de passe commun : `LABO_MOT_DE_PASSE` dans `.env.lab`.", "",
          "| Identité | Tenant | Rôle | E-mail | UUID |", "|---|---|---|---|---|"]
    if cfg.get("anonyme", True):
        md.append("| anon | aucun | non connecté | | |")
    md += [f"| {i} | {c} | {r} | {e} | `{u}` |" for (i, c, r, e, u) in ident]
    md += ["", "## Marqueurs de données", "", "| Table | Tenant | Marqueur |", "|---|---|---|"]
    md += [f"| {t} | {c} | `{m}` |" for (t, c, m) in marqueurs]
    for spec in cfg.get("fichiers") or []:
        for t in tenants:
            for n in range(1, int(spec.get("par_tenant", 1)) + 1):
                md.append(f"| storage:{spec['bucket']} | {t['code']} | `SECRET-TENANT-{t['code']}-{100 + n:03d}` |")
    with open(os.path.join(lab, "identites.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")

    print(f"{len(ident)} comptes, {len(tenants)} tenants, {len(marqueurs)} lignes marquées.")
    print("Écrits : supabase/seeds/90_labo_identites.sql, security/labo/{.env.lab, labo.sh, labo_verifier.py, labo_fichiers.py, identites.md}")
    cfgtoml = os.path.join(racine, "supabase", "config.toml")
    if os.path.exists(cfgtoml) and "seeds/" not in open(cfgtoml, encoding="utf-8").read():
        print("À FAIRE dans supabase/config.toml, section [db.seed] :")
        print('  enabled = true\n  sql_paths = ["./seed.sql", "./seeds/*.sql"]')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    g = s.add_parser("gabarit")
    g.add_argument("racine")
    g.add_argument("--app")
    g.add_argument("--tenants", default="A,B")
    g.add_argument("--roles", default="owner,admin,member,viewer")
    g.add_argument("--forcer", action="store_true")
    r = s.add_parser("generer")
    r.add_argument("racine")
    a = p.parse_args()
    {"gabarit": cmd_gabarit, "generer": cmd_generer}[a.cmd](a)


if __name__ == "__main__":
    main()
