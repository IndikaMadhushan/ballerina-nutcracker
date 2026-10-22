# =============================================================================
# Gateway Proxy — builds the Nutcracker runtime + our Ballerina policy engine
# and bakes it into a minimal runtime image.
#
# The Ballerina sources under this directory implement:
#   - the policy framework (policy/registry/chain/proxy/strutil .bal)
#   - the jwt-auth:v1 policy (jwt/jwks/jwt_auth .bal)
#   - the route wiring + policy config (main.bal, policies.json)
#
# Run:  docker build -t indikamadhushan/nutcracker-gateway:v1.0.2 \
#                      -t indikamadhushan/nutcracker-gateway:latest .
#       docker run -p 8080:8080 -e UPSTREAM_URL=... -e JWKS_URI=... \
#                  indikamadhushan/nutcracker-gateway:v1.0.2
# =============================================================================

# Image version (keep in sync with the `version` in Ballerina.toml).


# --- Stage 1: build the Ballerina toolchain and compile the project ----------
FROM golang:latest AS builder

# Nutcracker revision to build. Pinned to the commit the local toolchain is
# based on: object-type method visibility semantics (private vs public) changed
# on upstream main after this commit, and this code targets the pinned one.
ARG NUTCRACKER_REF=0c1fb6d33

WORKDIR /build

# 1. Clone Nutcracker and build the CLI plus the stripped-down runtime.
#    `bal build` needs both binaries (see the project README).
RUN git clone https://github.com/ballerina-nutcracker/ballerina.git nutcracker && \
    cd nutcracker && \
    git checkout "${NUTCRACKER_REF}" && \
    go build -o bal ./cli/cmd && \
    go build -o balrt ./cli/internal/balrt

WORKDIR /build/project

# 2. Initialize a new Ballerina project (creates gateway_proxy/).
RUN /build/nutcracker/bal new gateway_proxy

# 3. Inject our sources: project manifest + every policy-engine .bal file.
COPY *.bal Ballerina.toml ./gateway_proxy/

# 4. Compile the standalone binary using Nutcracker.
WORKDIR /build/project/gateway_proxy
RUN /build/nutcracker/bal build

# --- Stage 2: minimal production image --------------------------------------
FROM debian:bookworm-slim

ARG VERSION
LABEL org.opencontainers.image.title="nutcracker-gateway" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="Ballerina Nutcracker gateway with a config-driven policy engine and an RS256 JWT auth policy"

WORKDIR /app

# Compiled gateway binary (policies are linked in).
COPY --from=builder /build/project/gateway_proxy/target/bin/gateway_proxy .

# Policy-engine config, read at startup. Point POLICY_CONFIG elsewhere to
# mount a different config.
COPY policies.json ./policies.json
ENV POLICY_CONFIG=/app/policies.json

# Port the gateway listens on.
EXPOSE 8080

# Run the native binary.
CMD ["./gateway_proxy"]
