#!/usr/bin/env bash
#
# Configure the GitHub side of this repository the same way as
# zauberhaus/reflect_utils, so the workflows in .github/workflows work:
#
#   1. Repository settings: auto-merge, delete branches on merge, merge
#      commit message format, no wiki or projects.
#   2. Secret scanning with push protection.
#   3. Actions: read-only default token, workflows may approve pull requests.
#   4. The dev branch (created from the default branch if it is missing).
#   5. CodeQL default setup (the main ruleset requires its results).
#   6. The RELEASE_TOKEN secret used by the release-please workflow to create
#      and merge the release pull request.
#   7. The "main" ruleset on the default branch: no deletion or force
#      pushes, signed commits, the "test" check from tests.yml, changes only
#      through pull requests, CodeQL, code quality and Copilot review.
#
# The ruleset is applied last because it blocks direct pushes to main and
# requires the "test" check. Get .github/workflows onto main (through a pull
# request) before applying it, and make sure tests.yml has no path filter and
# release-please uses RELEASE_TOKEN: a required check that is never reported
# blocks the pull request forever.
#
# The script is idempotent and can be re-run. Requires an authenticated
# GitHub CLI (gh) with admin rights on the repository.

set -euo pipefail

REPO=
DRY_RUN=false
DO_SECRET=true
DO_RULESET=true
FORCE_SECRET=false
FAILED=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [-r OWNER/REPO] [-n] [-S] [-R] [-f] [-h]

  -r OWNER/REPO  repository to configure (default: the repository of the
                 current directory)
  -n             dry run: only read from GitHub and print what would change
  -S             skip the RELEASE_TOKEN secret
  -R             skip the main ruleset
  -f             replace RELEASE_TOKEN even if it already exists
  -h             show this help

The RELEASE_TOKEN value is taken from the environment variable of the same
name, or asked for interactively. It must be a personal access token that
may merge pull requests in this repository (classic: "repo" scope;
fine-grained: contents and pull requests write access).
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while getopts "r:nSRfh" opt; do
  case "$opt" in
    r) REPO=$OPTARG ;;
    n) DRY_RUN=true ;;
    S) DO_SECRET=false ;;
    R) DO_RULESET=false ;;
    f) FORCE_SECRET=true ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

# api_write METHOD PATH [JSON]: send a change to GitHub, or print it in dry-run mode.
api_write() {
  local method=$1 path=$2 body=${3:-}

  if $DRY_RUN; then
    printf '    [dry-run] %s %s\n' "$method" "$path"
    if [ -n "$body" ]; then
      printf '%s\n' "$body" | sed 's/^/        /'
    fi
    return 0
  fi

  # gh prints the error details (which field was rejected and why) in the
  # response body, so keep it and show it when the call fails.
  local out
  if [ -n "$body" ]; then
    out=$(printf '%s' "$body" | gh api -X "$method" "$path" --input - 2>&1) || {
      printf '%s\n' "$out" >&2
      return 1
    }
  else
    out=$(gh api -X "$method" "$path" 2>&1) || {
      printf '%s\n' "$out" >&2
      return 1
    }
  fi
}

# step NAME FUNCTION: run a step; a failure is reported at the end and does
# not stop the remaining steps. Step functions must return their own status
# (set -e does not apply inside them).
step() {
  local name=$1
  shift
  log "$name"
  if ! "$@"; then
    warn "$name failed"
    FAILED+=("$name")
  fi
}

configure_repo() {
  api_write PATCH "repos/$REPO" '{
  "has_issues": true,
  "has_wiki": false,
  "has_projects": false,
  "allow_auto_merge": true,
  "delete_branch_on_merge": true,
  "allow_merge_commit": true,
  "allow_squash_merge": true,
  "allow_rebase_merge": true,
  "merge_commit_title": "MERGE_MESSAGE",
  "merge_commit_message": "PR_TITLE"
}'
}

configure_security() {
  api_write PATCH "repos/$REPO" '{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"}
  }
}'
}

configure_actions() {
  api_write PUT "repos/$REPO/actions/permissions/workflow" '{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": true
}'
}

ensure_dev_branch() {
  local default sha

  if gh api "repos/$REPO/branches/dev" >/dev/null 2>&1; then
    echo "    dev already exists"
    return 0
  fi

  default=$(gh api "repos/$REPO" --jq .default_branch) || return 1
  sha=$(gh api "repos/$REPO/git/ref/heads/$default" --jq .object.sha) || return 1
  api_write POST "repos/$REPO/git/refs" "{\"ref\": \"refs/heads/dev\", \"sha\": \"$sha\"}"
}

# Go only, on purpose: with the "actions" language the main ruleset waits for
# an Actions result on every pull request, but CodeQL skips that analysis when
# no workflow file changed (e.g. the CHANGELOG-only release-please PR), so
# such a PR could never be merged.
configure_codeql() {
  api_write PATCH "repos/$REPO/code-scanning/default-setup" '{
  "state": "configured",
  "languages": ["go"],
  "query_suite": "extended",
  "threat_model": "remote"
}'
}

configure_secret() {
  local existing token=${RELEASE_TOKEN:-}

  existing=$(gh secret list -R "$REPO" --json name --jq '.[].name') || return 1
  if ! $FORCE_SECRET && grep -qx RELEASE_TOKEN <<<"$existing"; then
    echo "    RELEASE_TOKEN already exists (use -f to replace it)"
    return 0
  fi

  if $DRY_RUN; then
    echo "    [dry-run] would set the RELEASE_TOKEN secret"
    return 0
  fi

  if [ -z "$token" ] && [ -t 0 ]; then
    read -r -s -p "    RELEASE_TOKEN value (input hidden): " token
    echo
  fi

  if [ -z "$token" ]; then
    warn "RELEASE_TOKEN is not set: export it and re-run, or run: gh secret set RELEASE_TOKEN -R $REPO"
    return 1
  fi

  printf '%s' "$token" | gh secret set RELEASE_TOKEN -R "$REPO"
}

configure_ruleset() {
  local body id

  body=$(cat <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
  },
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_signatures"},
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [{"context": "test"}]
      }
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "required_reviewers": [],
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      }
    },
    {
      "type": "code_scanning",
      "parameters": {
        "code_scanning_tools": [
          {
            "tool": "CodeQL",
            "security_alerts_threshold": "medium_or_higher",
            "alerts_threshold": "errors_and_warnings"
          }
        ]
      }
    },
    {"type": "code_quality", "parameters": {"severity": "warnings"}},
    {
      "type": "copilot_code_review",
      "parameters": {"review_on_push": true, "review_draft_pull_requests": true}
    }
  ]
}
JSON
  )

  id=$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name == "main") | .id' | head -n 1) || return 1
  if [ -n "$id" ]; then
    echo "    updating existing ruleset $id"
    api_write PUT "repos/$REPO/rulesets/$id" "$body"
  else
    api_write POST "repos/$REPO/rulesets" "$body"
  fi
}

command -v gh >/dev/null || die "gh (GitHub CLI) is required"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"

if [ -z "$REPO" ]; then
  REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null) ||
    die "cannot detect the repository; run inside a clone or pass -r OWNER/REPO"
fi
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository '$REPO' (expected OWNER/REPO)"

[ "$(gh api "repos/$REPO" --jq .permissions.admin)" = "true" ] || die "admin permission on $REPO is required"

if $DRY_RUN; then
  log "Dry run for $REPO: nothing will be changed"
else
  log "Configuring $REPO"
fi

step "Repository settings" configure_repo
step "Secret scanning" configure_security
step "Actions permissions" configure_actions
step "dev branch" ensure_dev_branch
step "CodeQL default setup" configure_codeql
if $DO_SECRET; then
  step "RELEASE_TOKEN secret" configure_secret
fi
if $DO_RULESET; then
  step "main ruleset" configure_ruleset
fi

echo
if [ "${#FAILED[@]}" -gt 0 ]; then
  warn "these steps failed: ${FAILED[*]}"
  exit 1
fi

log "Done"
if $DO_RULESET && ! $DRY_RUN; then
  echo "    main now requires pull requests and signed commits; push the workflows through a PR."
fi
