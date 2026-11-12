#!/bin/sh
# cspell:words govulncheck gosec securego
# Run go vet (suspicious constructs), govulncheck (known vulnerabilities), gosec (static security analysis)
# and gitleaks (hardcoded secrets in the working tree and git history).
set -u

status=0

# Pinned so a run does not depend on what "latest" resolves to (CI once picked
# an old govulncheck whose golang.org/x/tools no longer builds with new Go).
GOVULNCHECK_VERSION=v1.9.0
GOSEC_VERSION=v2.30.0
GITLEAKS_VERSION=v8.30.1

cd "$(dirname "$0")/.."

echo "==> go vet"
go vet ./... || status=1

echo "==> govulncheck"
go run golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION ./... || status=1

echo "==> gosec"
go run github.com/securego/gosec/v2/cmd/gosec@$GOSEC_VERSION ./... || status=1

echo "==> gitleaks (working tree)"
go run github.com/zricethezav/gitleaks/v8@$GITLEAKS_VERSION dir --no-banner --redact . || status=1

echo "==> gitleaks (git history)"
go run github.com/zricethezav/gitleaks/v8@$GITLEAKS_VERSION git --no-banner --redact . || status=1

if [ $status -ne 0 ]; then
  echo "FAILED!"
  exit 1
fi
echo "OK"
