# Grafana with both Vulnobs plugins baked in. Built, scanned, signed and
# SBOM-attested by .github/workflows/image.yml.
#
# The build stages run on the build machine's own platform and cross-compile
# the Go backends, so a multi-arch build needs no emulation. Base images are
# pinned by digest; Dependabot keeps them current.

# --- Frontend: webpack bundles (architecture-independent) ---
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:ef24c5053d50fdc3e4e56eb4e7ddb7861874ab0fdc797046ba897581deb8e868 AS frontend
WORKDIR /src/rupesh-vulnobs-app
COPY rupesh-vulnobs-app/package.json rupesh-vulnobs-app/package-lock.json rupesh-vulnobs-app/.npmrc ./
RUN npm ci --no-audit --no-fund
WORKDIR /src/rupesh-vulnobs-datasource
COPY rupesh-vulnobs-datasource/package.json rupesh-vulnobs-datasource/package-lock.json rupesh-vulnobs-datasource/.npmrc ./
RUN npm ci --no-audit --no-fund
WORKDIR /src
COPY rupesh-vulnobs-app/ rupesh-vulnobs-app/
COPY rupesh-vulnobs-datasource/ rupesh-vulnobs-datasource/
WORKDIR /src/rupesh-vulnobs-app
RUN npm run build
WORKDIR /src/rupesh-vulnobs-datasource
RUN npm run build

# --- Backend: Go plugin binaries for the target architecture ---
FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS backend
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local
RUN go install github.com/magefile/mage@v1.17.2
# The plugin SDK's mage target for each supported architecture.
RUN case "$TARGETARCH" in \
      amd64) echo build:linux ;; \
      arm64) echo build:linuxARM64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac > /mage-target
WORKDIR /src/rupesh-vulnobs-app
COPY rupesh-vulnobs-app/go.mod rupesh-vulnobs-app/go.sum ./
RUN go mod download
WORKDIR /src/rupesh-vulnobs-datasource
COPY rupesh-vulnobs-datasource/go.mod rupesh-vulnobs-datasource/go.sum ./
RUN go mod download
WORKDIR /src
COPY rupesh-vulnobs-app/ rupesh-vulnobs-app/
COPY rupesh-vulnobs-datasource/ rupesh-vulnobs-datasource/
WORKDIR /src/rupesh-vulnobs-app
RUN mage -v "$(cat /mage-target)"
WORKDIR /src/rupesh-vulnobs-datasource
RUN mage -v "$(cat /mage-target)"

# --- The plugin files exactly as they ship (exported and scanned in CI) ---
FROM scratch AS plugins
COPY --from=frontend /src/rupesh-vulnobs-app/dist/ /rupesh-vulnobs-app/
COPY --from=backend /src/rupesh-vulnobs-app/dist/ /rupesh-vulnobs-app/
COPY --from=frontend /src/rupesh-vulnobs-datasource/dist/ /rupesh-vulnobs-datasource/
COPY --from=backend /src/rupesh-vulnobs-datasource/dist/ /rupesh-vulnobs-datasource/

# --- Runtime ---
FROM grafana/grafana:13.2.1@sha256:f772d434e8fab0049deb2b1b30abd43342bcfca1537614aa8d36080232cf4283
# Plugins live outside /var/lib/grafana so a data volume mounted there can't
# hide them. Preinstall is disabled so nothing is downloaded into the signed
# image at startup.
ENV GF_PATHS_PLUGINS=/usr/share/grafana/plugins-vulnobs \
    GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=rupesh-vulnobs-app,rupesh-vulnobs-datasource \
    GF_PLUGINS_PREINSTALL_DISABLED=true
COPY --from=plugins / /usr/share/grafana/plugins-vulnobs/
