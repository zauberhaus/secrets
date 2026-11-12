#!/bin/sh
# cspell:words govulncheck gosec securego
# Run govulncheck (known vulnerabilities), gosec (static security analysis)
# and gitleaks (hardcoded secrets in the working tree and git history).
set -u

status=0

cd "$(dirname "$0")/.."

echo "==> govulncheck"
go run golang.org/x/vuln/cmd/govulncheck@latest ./... || status=1

echo "==> gosec"
go run github.com/securego/gosec/v2/cmd/gosec@latest ./... || status=1

echo "==> gitleaks (working tree)"
go run github.com/zricethezav/gitleaks/v8@latest dir --no-banner --redact . || status=1

echo "==> gitleaks (git history)"
go run github.com/zricethezav/gitleaks/v8@latest git --no-banner --redact . || status=1

if [ $status -ne 0 ]; then
  echo "FAILED!"
  exit 1
fi
echo "OK"
