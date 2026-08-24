#!/bin/sh
# Create a new GitHub release (and the git tag it points at) for this
# repository. The tag name and the release title are always identical, e.g.
# tag v1.2.4 gets a release titled "v1.2.4". By default this bumps the patch
# component of the latest published release; --major or --minor bump those
# components instead (resetting the components below them to 0).
#
# The next version is computed from the latest *published release*, not the
# latest git tag: if the target tag already exists but has no matching
# release — e.g. a previous run tagged successfully and then failed to
# publish the release — re-running lands on that same tag again (rather than
# skipping past it) and moves it to the current HEAD instead of failing with
# "tag already exists". A tag that already has a release is left alone and
# the run fails, since that release has genuinely already been published.
#
# Usage: release.sh [-M|--major] [-m|--minor] [-n|--no-test] [-y|--yes] [--dry-run] [--notes TEXT] [-h|--help]
#
#   -M, --major     bump the major version (X+1.0.0)
#   -m, --minor     bump the minor version (X.Y+1.0)
#                   (default: bump the patch version, X.Y.Z+1)
#   -n, --no-test   skip building/vetting/testing before tagging
#   -y, --yes       skip the "old version -> new version" confirmation prompt
#       --dry-run   print the version this run would create and exit; no
#                   tag, push, or release is made
#       --notes TEXT  release notes (default: gh's auto-generated notes)
#   -h, --help      show this help
set -euo pipefail

BUMP=patch
RUN_TESTS=1
DRY_RUN=0
ASSUME_YES=0
NOTES=""

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -M|--major)   BUMP=major ;;
        -m|--minor)   BUMP=minor ;;
        -n|--no-test) RUN_TESTS=0 ;;
        -y|--yes)     ASSUME_YES=1 ;;
        --dry-run)    DRY_RUN=1 ;;
        --notes)      NOTES="$2"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

cd "$(dirname "$0")"

command -v gh > /dev/null 2>&1 || { echo "gh (GitHub CLI) is required" >&2; exit 1; }
command -v git > /dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

echo "==> fetching tags"
git fetch origin --tags --quiet

# latest_release prints the tag of the latest published GitHub release, or
# nothing if the repository has no releases yet. This deliberately ignores
# git tags that have no matching release (e.g. a stale tag left behind by a
# run that tagged successfully but failed to publish), so a retry recomputes
# the same next version instead of skipping past it.
latest_release() {
    local out
    # Try to get the tag name of the latest release
    if out="$(gh release view --json tagName -q .tagName 2>&1)"; then
        echo "$out"
        return 0
    fi
    
    # Convert output to lowercase to make matching easier
    local out_lower
    out_lower=$(echo "$out" | tr '[:upper:]' '[:lower:]')
    
    # Check for various "not found" messages returned by GitHub CLI
    if [[ "$out_lower" == *"no releases found"* ]] || [[ "$out_lower" == *"release not found"* ]] || [[ "$out_lower" == *"not found"* ]]; then
        echo "" # Return empty; next_version will default this to v0.0.0
        return 0
    fi

    # If it's a different error (e.g., network or auth), print it and fail
    echo "gh release view: $out" >&2
    return 1
}

# next_version prints the vX.Y.Z tag this run would create, given the
# latest published release and $BUMP.
next_version() {
    local latest="$1" major minor patch

    if [[ -z "$latest" ]]; then
        echo "v1.0.0"
        return
    fi

    if [[ ! "$latest" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo "latest release '$latest' is not a plain vX.Y.Z version; can't compute the next release" >&2
        return 1
    fi
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"

    case "$BUMP" in
        major) major=$((major + 1)); minor=0; patch=0 ;;
        minor) minor=$((minor + 1)); patch=0 ;;
        patch) patch=$((patch + 1)) ;;
    esac

    echo "v${major}.${minor}.${patch}"
}

latest="$(latest_release)" || exit 1
next="$(next_version "$latest")"

echo "latest release: ${latest:-(none)}"
echo "next release:   $next ($BUMP bump)"

if [[ $DRY_RUN -eq 1 ]]; then
    exit 0
fi

TAG_EXISTS=0
if git rev-parse "$next" > /dev/null 2>&1; then
    TAG_EXISTS=1
fi

if gh release view "$next" > /dev/null 2>&1; then
    echo "release $next already exists" >&2
    exit 1
fi

if [[ $TAG_EXISTS -eq 1 ]]; then
    echo "tag $next already exists but has no release — a previous run likely failed after tagging; it will be moved to HEAD"
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree is not clean; commit or stash changes before releasing" >&2
    exit 1
fi

# A release should always point at a commit the rest of the world can already
# see, not one that only exists locally.
branch="$(git symbolic-ref --short HEAD)"
local_rev="$(git rev-parse HEAD)"
remote_rev="$(git rev-parse "origin/$branch" 2> /dev/null || true)"
if [[ "$local_rev" != "$remote_rev" ]]; then
    echo "HEAD ($local_rev) differs from origin/$branch (${remote_rev:-unknown}); push $branch before releasing" >&2
    exit 1
fi

if [[ $ASSUME_YES -ne 1 ]]; then
    prompt="Release ${latest:-(none)} -> $next?"
    if [[ $TAG_EXISTS -eq 1 ]]; then
        prompt="$prompt (moves the existing $next tag to HEAD)"
    fi
    read -r -p "$prompt [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "aborted"; exit 1 ;;
    esac
fi

if [[ $RUN_TESTS -eq 1 ]]; then
    echo "==> building"
    go build ./...

    echo "==> vetting"
    go vet ./...

    echo "==> testing"
    go test ./...
fi

if [[ $TAG_EXISTS -eq 1 ]]; then
    echo "==> moving existing tag $next to HEAD"
    git tag -f -a "$next" -m "$next"
    git push origin "$next" --force
else
    echo "==> tagging $next"
    git tag -a "$next" -m "$next"
    git push origin "$next"
fi

echo "==> creating GitHub release $next"
if [[ -n "$NOTES" ]]; then
    gh release create "$next" --title "$next" --notes "$NOTES"
else
    gh release create "$next" --title "$next" --generate-notes
fi

echo
echo "done — $(gh release view "$next" --json url -q .url)"
