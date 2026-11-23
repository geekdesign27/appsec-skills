#!/usr/bin/env bash
# Laboratoire AppSec : une commande pour monter, une pour remettre à zéro (généré par appsec-labo).
# Usage, depuis la racine de l'app :  security/labo/labo.sh up | reset | verifier | down | statut
set -euo pipefail
cd "$(dirname "$0")/../.."
ENV_LAB=security/labo/.env.lab

garde() {
  # 1. Jamais la production : la CLI v3 est locale par défaut ; on refuse tout ce qui pourrait viser l'hébergé.
  if [ -n "${SUPABASE_YES:-}" ]; then echo "ARRÊT : SUPABASE_YES est exporté (la CLI ne demanderait plus confirmation)."; exit 1; fi
  if [ -n "${SUPABASE_ACCESS_TOKEN:-}" ]; then echo "ARRÊT : SUPABASE_ACCESS_TOKEN est défini. Ouvre un shell sans jeton d'accès au compte Supabase."; exit 1; fi
  if grep -Eq 'https?://[a-z0-9]{20}\.supabase\.co|sb_secret_[A-Za-z0-9_-]{20,}' "$ENV_LAB" 2>/dev/null; then
    echo "ARRÊT : $ENV_LAB contient une valeur de production."; exit 1; fi
  if ! grep -q '^SUPABASE_URL=http://\(127\.0\.0\.1\|localhost\)' "$ENV_LAB"; then
    echo "ARRÊT : SUPABASE_URL de $ENV_LAB n'est pas locale."; exit 1; fi
  command -v supabase >/dev/null || { echo "Supabase CLI absente (npm i -g supabase ou brew install supabase/tap/supabase)."; exit 1; }
}

case "${1:-}" in
  up)
    garde
    supabase start
    python3 security/labo/labo_verifier.py "${@:2}"
    ;;
  reset)
    garde
    # Rejoue toutes les migrations puis les seeds (dont seeds/90_labo_identites.sql). Local par défaut en CLI v3.
    supabase db reset
    python3 security/labo/labo_verifier.py "${@:2}"
    ;;
  verifier)
    garde
    python3 security/labo/labo_verifier.py "${@:2}"
    ;;
  statut)
    supabase status
    ;;
  down)
    supabase stop
    ;;
  *)
    echo "Usage : $0 up | reset | verifier | down | statut  [--sonde table:colonne]"; exit 2 ;;
esac
