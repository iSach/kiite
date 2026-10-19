#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$(brew --prefix libssh2)"
SSL="$(brew --prefix openssl@3)"
TEST_DIR="$(mktemp -d /private/tmp/kiite-transport.XXXXXX)"
PORT="${KIITE_TEST_PORT:-23299}"
SSHD_PID=""
cleanup() {
    if [ -n "$SSHD_PID" ]; then
        kill "$SSHD_PID" 2>/dev/null || true
        wait "$SSHD_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT HUP INT TERM
ssh-keygen -q -t ed25519 -N '' -f "$TEST_DIR/host"
ssh-keygen -q -t ed25519 -N '' -f "$TEST_DIR/client"
cp "$TEST_DIR/client.pub" "$TEST_DIR/authorized_keys"
cat > "$TEST_DIR/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TEST_DIR/host
PidFile $TEST_DIR/sshd.pid
AuthorizedKeysFile $TEST_DIR/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PubkeyAuthentication yes
StrictModes no
PermitRootLogin no
PrintMotd no
PrintLastLog no
AllowUsers $(id -un)
Subsystem sftp /usr/libexec/sftp-server
LogLevel ERROR
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
EOF
clang -Wall -Wextra -O2 -I"$ROOT/Sources" -I"$SSH/include" -I"$SSL/include" \
    "$ROOT/Sources/upload.c" "$ROOT/Tests/TransportTests.c" \
    -L"$SSH/lib" -lssh2 -L"$SSL/lib" -lcrypto -o "$TEST_DIR/transport-test"
PIN="$(python3 - "$TEST_DIR/host.pub" <<'PY'
import base64, hashlib, pathlib, sys
print(hashlib.sha256(base64.b64decode(pathlib.Path(sys.argv[1]).read_text().split()[1])).hexdigest())
PY
)"
/usr/sbin/sshd -D -e -f "$TEST_DIR/sshd_config" > "$TEST_DIR/sshd.log" 2>&1 &
SSHD_PID=$!
python3 - "$PORT" <<'PY'
import socket, sys, time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=.1): break
    except OSError: time.sleep(.05)
else: raise SystemExit('Local SSH fixture did not start')
PY
kill -0 "$SSHD_PID" || { cat "$TEST_DIR/sshd.log" >&2; exit 1; }
"$TEST_DIR/transport-test" "$TEST_DIR" "$(id -un)" "$TEST_DIR/client" "$PIN" "$PORT"
