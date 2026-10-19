#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${KIITE_BUILD_DIR:-$ROOT/build}/Kiite.app"
DESTINATION="${KIITE_INSTALL_DIR:-/Applications}"
test -d "$SOURCE" || { echo 'Run make build first.' >&2; exit 1; }
python3 - "$DESTINATION/Kiite.app/Contents/MacOS/Kiite" <<'PY'
import subprocess, sys
expected = sys.argv[1]
pids = subprocess.run(['pgrep', '-f', r'/Kiite\.app/Contents/MacOS/Kiite( |$)'], capture_output=True, text=True).stdout.split()
for pid in pids:
    command = subprocess.run(['ps', '-p', pid, '-o', 'command='], capture_output=True, text=True).stdout.strip()
    if command == expected or command.startswith(expected + ' '):
        raise SystemExit('Quit Kiite before installing the update.')
PY
test -w "$DESTINATION" || { echo "$DESTINATION is not writable." >&2; exit 1; }
STAGING="$(mktemp -d "$DESTINATION/.kiite-install.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
ditto "$SOURCE" "$STAGING/Kiite.app"
codesign --verify --deep --strict "$STAGING/Kiite.app"
if [ -e "$DESTINATION/Kiite.app" ]; then
    mv "$DESTINATION/Kiite.app" "$STAGING/Previous.app"
fi
if ! mv "$STAGING/Kiite.app" "$DESTINATION/Kiite.app"; then
    if [ -e "$STAGING/Previous.app" ]; then mv "$STAGING/Previous.app" "$DESTINATION/Kiite.app"; fi
    exit 1
fi
echo "Installed $DESTINATION/Kiite.app"
