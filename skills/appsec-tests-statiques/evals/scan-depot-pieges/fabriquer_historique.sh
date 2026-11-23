#!/usr/bin/env bash
# Construit un historique git réaliste : un secret fictif est commité puis « supprimé » dans le commit suivant.
set -eu
cd "${1:-.}/chantier-pro"
git init -q; git config user.email labo@labo.test; git config user.name labo
SECRET="sb_secret_$(printf 'FICTIF-POUR-TEST-%s' labo2026xyzABCDEF)"
printf 'VITE_SUPABASE_URL=http://127.0.0.1:54321\nSUPABASE_SECRET_KEY=%s\n' "$SECRET" > .env
git add -A; git commit -qm "init chantier-pro"
git rm -q --cached .env; rm .env; printf '.env\n' > .gitignore
git add -A; git commit -qm "retire le .env"
