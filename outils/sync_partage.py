#!/usr/bin/env python3
"""Copie partage/ dans chaque skill et vérifie que les copies sont identiques.

Usage (depuis la racine du dépôt appsec-skills) :
  python3 outils/sync_partage.py            # copie puis vérifie
  python3 outils/sync_partage.py --verifier # vérifie seulement (code 1 si écart)

Source unique : partage/references/ -> skills/<skill>/references/partage/
                partage/scripts/    -> skills/<skill>/scripts/partage/
"""
import hashlib
import os
import shutil
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIRES = [("partage/references", "references/partage"), ("partage/scripts", "scripts/partage")]


def empreinte(dossier):
    h = hashlib.sha256()
    for racine, _, fichiers in sorted(os.walk(dossier)):
        for f in sorted(fichiers):
            if f.endswith(".pyc") or "__pycache__" in racine:
                continue
            p = os.path.join(racine, f)
            h.update(os.path.relpath(p, dossier).encode())
            h.update(open(p, "rb").read())
    return h.hexdigest()[:12]


def main():
    verifier = "--verifier" in sys.argv
    skills = sorted(d for d in os.listdir(os.path.join(RACINE, "skills"))
                    if os.path.isfile(os.path.join(RACINE, "skills", d, "SKILL.md")))
    ecarts = 0
    for src_rel, dst_rel in PAIRES:
        src = os.path.join(RACINE, src_rel)
        ref = empreinte(src)
        for s in skills:
            dst = os.path.join(RACINE, "skills", s, dst_rel)
            if not verifier:
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            ok = os.path.isdir(dst) and empreinte(dst) == ref
            ecarts += not ok
            print(f"{'OK ' if ok else 'ÉCART'} {s}/{dst_rel} ({ref})")
    sys.exit(1 if ecarts else 0)


if __name__ == "__main__":
    main()
