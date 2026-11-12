#!/bin/sh

cd "$(dirname "$0")"

cd ..

# package.json exists only to pin the cspell tooling below; it's
# gitignored, so recreate it on demand rather than committing it. Versions
# are pinned to "latest" and npm install runs unconditionally so every run
# picks up whatever is newest on the registry.
if [ ! -f package.json ]; then
	cat > package.json << 'EOF'
{
  "private": true,
  "devDependencies": {
    "cspell": "latest",
    "@cspell/dict-en-au": "latest",
    "@cspell/dict-en-gb": "latest"
  }
}
EOF
fi

npm update

npx cspell -c cspell.config.yaml .