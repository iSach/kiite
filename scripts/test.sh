#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIITE_BUILD_DIR="$ROOT/build/tests" KIITE_TESTING=1 "$ROOT/scripts/build.sh"
"$ROOT/build/tests/Kiite.app/Contents/MacOS/Kiite" --self-test
"$ROOT/scripts/test-transport.sh"
