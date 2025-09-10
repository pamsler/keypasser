#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

has() { command -v "$1" >/dev/null 2>&1; }
env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }
semvers_only() { grep -E '^[vV]?[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$' | sed -E 's/^[vV]//' ; }
pick_max() { sort -V | tail -n1; }

DC="docker compose"; $DC version >/dev/null 2>&1 || DC="docker-compose"

REPO="${DOCKERHUB_REPO:-$(env_get DOCKERHUB_REPO)}"
REPO="${REPO:-pamsler/keypasser}"
CUR="$(env_get KP_VERSION)"; CUR="${CUR:-0.0.0}"

TO_TAG=""; CHECK_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --to) TO_TAG="${2:-}"; shift 2 ;;
    --check) CHECK_ONLY=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

fetch_ns_all() {
  local ns name url page res
  ns="${REPO%%/*}"
  name="${REPO#*/}"
  url="https://hub.docker.com/v2/namespaces/${ns}/repositories/${name}/tags?page_size=100"
  page=1
  while :; do
    res="$(curl -fsSL "${url}&page=${page}" -H 'Accept: application/json' -H 'User-Agent: keypasser-updater/2' || true)"
    [ -n "$res" ] || break
    printf '%s\n' "$res" | grep -o '"name":"[^"]*"' | cut -d'"' -f4
    printf '%s' "$res" | grep -q '"next":null' && break
    page=$((page+1))
  done | sed '/^$/d' | sort -u
}
fetch_registry_all() {
  local tok
  tok="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" \
         -H 'User-Agent: keypasser-updater/2' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "${tok:-}" ] || return 0
  curl -fsSL "https://registry-1.docker.io/v2/${REPO}/tags/list" \
    -H "Authorization: Bearer ${tok}" -H 'Accept: application/json' -H 'User-Agent: keypasser-updater/2' \
  | tr '[],"' '\n' | sed -n 's/^[[:space:]]*\([^[:space:]]\+\)[[:space:]]*$/\1/p' \
  | sed -n '1,/^tags$/d;p' | sed '/^$/d' | sort -u
}
get_latest() { { fetch_ns_all || true; fetch_registry_all || true; } | semvers_only | pick_max; }

LATEST="${TO_TAG:-$(get_latest)}"
[ -n "$LATEST" ] || { echo "Could not fetch tags (Repo: $REPO)"; exit 2; }

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "Repo:   $REPO"
  echo "Local:  $CUR"
  echo "Remote: $LATEST"
  exit 0
fi

if [ -z "$TO_TAG" ]; then
  if [ "$CUR" = "$LATEST" ] || [ "$(printf '%s\n%s\n' "$CUR" "$LATEST" | sort -V | tail -n1)" = "$CUR" ]; then
    echo "Already up to date ($CUR)."
    exit 0
  fi
fi

echo "Update: $CUR -> $LATEST"
if grep -qE '^KP_VERSION=' "$ENV_FILE" 2>/dev/null; then
  sed -i.bak -E "s/^KP_VERSION=.*/KP_VERSION=$LATEST/" "$ENV_FILE"
else
  echo "KP_VERSION=$LATEST" >> "$ENV_FILE"
fi
grep -qE '^DOCKERHUB_REPO=' "$ENV_FILE" 2>/dev/null || echo "DOCKERHUB_REPO=$REPO" >> "$ENV_FILE"

$DC -f "$COMPOSE_FILE" pull app
$DC -f "$COMPOSE_FILE" up -d app
echo "Done."
