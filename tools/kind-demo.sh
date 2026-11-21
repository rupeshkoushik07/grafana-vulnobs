#!/usr/bin/env bash
# Run the whole thing on your own machine, from nothing: a local Kubernetes
# cluster (kind), Grafana with the Vulnobs app built from this checkout, the
# cluster scan, the Scan now button and the workloads view, plus a few old
# images to find.
#
#   tools/kind-demo.sh up               build, create the cluster, deploy everything
#   tools/kind-demo.sh open             forward Grafana to http://localhost:3000
#   tools/kind-demo.sh add-vulnerable   deploy a Log4Shell test app, to watch it appear
#   tools/kind-demo.sh down             delete the cluster
#
# Needs docker, kind, kubectl, tk (Grafana Tanka), python3 and openssl.
# macOS: brew install kind kubectl tanka
#
# Demo only. It turns on anonymous Editor access, Scan now and the workloads
# view; read deploy/tanka/README.md before doing that anywhere shared.
set -euo pipefail

CLUSTER="${VULNOBS_DEMO_CLUSTER:-vulnobs-demo}"
IMAGE_TAG=demo
PORT="${VULNOBS_DEMO_PORT:-3000}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
k() { kubectl --context "kind-$CLUSTER" "$@"; }

need() {
  local missing=0
  for tool in "$@"; do
    if ! command -v "$tool" > /dev/null; then
      echo "missing: $tool" >&2
      missing=1
    fi
  done
  if [ "$missing" = 1 ]; then
    echo "Install the tools above first (macOS: brew install kind kubectl tanka)." >&2
    exit 1
  fi
}

up() {
  need docker kind kubectl tk python3 openssl

  echo "==> Building the Vulnobs image from this checkout (a few minutes the first time)"
  docker build -t "vulnobs:$IMAGE_TAG" "$root"

  if ! kind get clusters | grep -qx "$CLUSTER"; then
    echo "==> Creating the kind cluster $CLUSTER"
    kind create cluster --name "$CLUSTER"
  fi
  echo "==> Loading the image into the cluster"
  kind load docker-image "vulnobs:$IMAGE_TAG" --name "$CLUSTER"

  echo "==> PostgreSQL and storage credentials"
  k create namespace vulnobs --dry-run=client -o yaml | k apply -f -
  if ! k -n vulnobs get deployment postgres > /dev/null 2>&1; then
    k -n vulnobs create deployment postgres --image=postgres:17-alpine --port=5432
    k -n vulnobs set env deployment/postgres POSTGRES_DB=vulnobs POSTGRES_USER=vulnobs POSTGRES_PASSWORD=vulnobs-demo
    k -n vulnobs expose deployment postgres --port=5432
  fi
  k -n vulnobs rollout status deployment/postgres --timeout=5m
  if ! k -n vulnobs get secret vulnobs-storage > /dev/null 2>&1; then
    signing_key="$(openssl rand -hex 32)"
    storage_token="$(VULNOBS_TOKEN_SIGNING_KEY="$signing_key" python3 "$root/tools/create-storage-token.py" --tenant-id demo)"
    k -n vulnobs create secret generic vulnobs-storage \
      --from-literal=database-url='postgres://vulnobs:vulnobs-demo@postgres:5432/vulnobs?sslmode=disable' \
      --from-literal=token-signing-key="$signing_key" \
      --from-literal=storage-token="$storage_token"
  fi

  echo "==> Deploying Grafana, the storage API and the scan job"
  # Rendered and piped to kubectl, so the tracked Tanka spec.json is not touched.
  # The stack's own namespace is left out of the scan: its Grafana image only
  # exists inside this cluster, so no scanner could pull it.
  (cd "$root/deploy/tanka" && tk show environments/default --dangerous-allow-redirect \
    --tla-str imageRepository=vulnobs --tla-str "imageTag=$IMAGE_TAG" \
    --tla-code scanNow=true --tla-code showWorkloads=true \
    --tla-code 'excludeNamespaces=["kube-system","kube-public","kube-node-lease","local-path-storage","vulnobs"]') |
    k apply -f -
  # Pick up a rebuilt image on a second run.
  k -n vulnobs rollout restart deployment/grafana deployment/vulnobs-storage > /dev/null
  k -n vulnobs rollout status deployment/vulnobs-storage --timeout=5m
  k -n vulnobs rollout status deployment/grafana --timeout=5m

  echo "==> Demo workloads"
  k apply -f "$root/examples/kind-demo/workloads.yaml"

  cat <<MSG

Ready. Next:
  tools/kind-demo.sh open
then, in the browser, More apps -> Vulnobs -> Assets. Your workloads are listed as
"not scanned yet"; click Scan now.
MSG
}

open_grafana() {
  need kubectl
  echo "Grafana: http://localhost:$PORT/a/rupeshkoushik07-vulnobs-app/assets   (Ctrl+C to stop)"
  k -n vulnobs port-forward svc/grafana "$PORT:3000"
}

add_vulnerable() {
  need kubectl
  k apply -f "$root/examples/kind-demo/payments-api.yaml"
  echo "Deployed payments-api. It shows up on the Assets page within 15 seconds; then click Scan now."
}

down() {
  need kind
  kind delete cluster --name "$CLUSTER"
}

case "${1:-}" in
  up) up ;;
  open) open_grafana ;;
  add-vulnerable) add_vulnerable ;;
  down) down ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
