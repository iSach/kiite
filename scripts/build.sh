#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${KIITE_BUILD_DIR:-$ROOT/build}"
APP="$BUILD/Kiite.app"
IDENTITY="${KIITE_SIGN_IDENTITY:--}"
SIGN_ARGS=(--force --sign "$IDENTITY")
# Library validation requires a Team ID. Local ad-hoc builds have none; builds
# using a signing identity retain hardened runtime and library validation.
if [ "$IDENTITY" != - ]; then SIGN_ARGS+=(--options runtime); fi
ARCH="$(uname -m)"
SDK="$(xcrun --show-sdk-path)"
command -v brew >/dev/null || { echo 'Install Homebrew first: https://brew.sh' >&2; exit 1; }
SSH="$(brew --prefix libssh2)"
SSL="$(brew --prefix openssl@3)"
LIBRARIES=("$SSH/lib/libssh2.1.dylib" "$SSL/lib/libssl.3.dylib" "$SSL/lib/libcrypto.3.dylib")
for lib in "${LIBRARIES[@]}"; do
    test -f "$lib" || { echo 'Run: brew install libssh2 openssl@3' >&2; exit 1; }
done
# Declare the real minimum supported by the linked libraries, not just Swift.
MINIMUM="$(python3 - "${LIBRARIES[@]}" <<'PY'
import re, subprocess, sys
versions = [(14, 0)]
for path in sys.argv[1:]:
    text = subprocess.check_output(['xcrun', 'vtool', '-show-build', path], text=True)
    versions += [tuple(map(int, s.split('.'))) for s in re.findall(r'\bminos\s+([\d.]+)', text)]
print('.'.join(map(str, max(versions))))
PY
)"
TARGET="$ARCH-apple-macos$MINIMUM"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Frameworks" "$APP/Contents/Resources/Licenses"
SWIFT_SOURCES=("$ROOT/Sources/"*.swift)
SWIFT_FLAGS=(-parse-as-library -O)
if [ "${KIITE_TESTING:-0}" = 1 ]; then
    SWIFT_SOURCES+=("$ROOT/Tests/LocalProofs.swift")
    SWIFT_FLAGS+=(-D KIITE_TESTING)
fi
echo "Building Kiite for $ARCH, macOS $MINIMUM+"
clang -target "$TARGET" -isysroot "$SDK" -O2 -Wall -Wextra \
    -I"$SSH/include" -I"$SSL/include" -c "$ROOT/Sources/upload.c" -o "$BUILD/upload.o"
swiftc -target "$TARGET" -sdk "$SDK" \
    "${SWIFT_FLAGS[@]}" -import-objc-header "$ROOT/Sources/upload.h" \
    -framework AppKit -framework SwiftUI -framework CryptoKit -framework Security -framework ServiceManagement \
    -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
    -L"$SSH/lib" -lssh2 -L"$SSL/lib" -lssl -lcrypto -lsqlite3 \
    "${SWIFT_SOURCES[@]}" "$BUILD/upload.o" \
    -o "$APP/Contents/MacOS/Kiite"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
python3 - "$APP/Contents/Info.plist" "$MINIMUM" "${KIITE_TESTING:-0}" <<'PY'
import plistlib, sys
path = sys.argv[1]
with open(path, 'rb') as f: info = plistlib.load(f)
info['LSMinimumSystemVersion'] = sys.argv[2]
if sys.argv[3] == '1': info['CFBundleIdentifier'] = 'com.isach.kiite.tests'
with open(path, 'wb') as f: plistlib.dump(info, f)
PY
for lib in "${LIBRARIES[@]}"; do cp -L "$lib" "$APP/Contents/Frameworks/"; done
python3 - "$APP" <<'PY'
import pathlib, subprocess, sys
app = pathlib.Path(sys.argv[1])
frameworks = app / 'Contents/Frameworks'
names = {p.name for p in frameworks.iterdir()}
for binary in [*frameworks.iterdir(), app / 'Contents/MacOS/Kiite']:
    if binary.parent == frameworks:
        subprocess.run(['install_name_tool', '-id', '@rpath/' + binary.name, str(binary)], check=True)
    listing = subprocess.check_output(['otool', '-L', str(binary)], text=True)
    for line in listing.splitlines()[1:]:
        dep = line.strip().split(' (')[0]
        name = pathlib.Path(dep).name
        replacement = '@rpath/' + name
        if name in names and dep != replacement:
            subprocess.run(['install_name_tool', '-change', dep, replacement, str(binary)], check=True)
        elif dep.startswith('/') and not dep.startswith(('/usr/lib/', '/System/Library/')):
            raise SystemExit('Unbundled dependency: ' + dep)
PY
cp "$ROOT/ThirdParty/"*.txt "$APP/Contents/Resources/Licenses/"
cp "$ROOT/LICENSE" "$APP/Contents/Resources/Licenses/Kiite.txt"
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/"
for lib in "$APP/Contents/Frameworks/"*.dylib; do
    codesign "${SIGN_ARGS[@]}" "$lib"
done
codesign "${SIGN_ARGS[@]}" \
    --entitlements "$ROOT/Resources/Kiite.entitlements" "$APP"
codesign --verify --deep --strict "$APP"
echo "Built $APP"
