#!/usr/bin/env bash
# Remplace chaque « image: nom:tag » du compose d'outils par « image: nom@sha256:... » (digest réellement téléchargé).
# Usage : assets/epingler_images.sh security/labo/docker-compose.outils.yml
# Une image introuvable est signalée et laissée telle quelle : vérifier son nom sur le registre officiel de l'outil.
set -uo pipefail
F="${1:?chemin du docker-compose.outils.yml}"
cp "$F" "$F.avant-epinglage"
grep -E '^\s+image:\s' "$F" | sed -E 's/^\s+image:\s+([^ #]+).*/\1/' | sort -u | while read -r img; do
  case "$img" in *@sha256:*) echo "déjà épinglée : $img"; continue ;; esac
  if docker pull -q "$img" >/dev/null 2>&1; then
    dig=$(docker inspect --format '{{index .RepoDigests 0}}' "$img" 2>/dev/null)
    if [ -n "$dig" ]; then
      sed -i.bak "s#image: $img#image: $dig  \# était $img#" "$F" && rm -f "$F.bak"
      echo "épinglée : $img -> $dig"
    fi
  else
    echo "ÉCHEC du téléchargement : $img (nom à vérifier ou registre inaccessible)"
  fi
done
echo "Vérifier la version de Trivy : docker run --rm \$(grep -oE 'aquasec/trivy@sha256:[a-f0-9]+' $F) --version (≥ 0.76.2)"
