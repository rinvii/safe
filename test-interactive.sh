#!/bin/bash
set -euo pipefail

SUDOPASS="secret"
PASS="hello"
ARGS=""

rm -f out.enc out plain

make clean

expect <<EOF
    spawn make release_embed
    expect "New password:"
    send "$PASS\r"
    expect eof
EOF

expect <<EOF
    spawn sudo ./build/launch
    expect -re "(?i)password.*:"
    send -- "$SUDOPASS\r"
    sleep 1
    send "$PASS\r"
    sleep 1
    send -- "$ARGS\r"
    expect eof
EOF