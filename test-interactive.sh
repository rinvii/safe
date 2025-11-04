#!/bin/bash
set -euo pipefail

SUDOPASS=""
PASS="hello"
ARGS=""

rm -f out.enc out plain

make clean

expect <<EOF
    log_user 1
    exp_internal 1
    spawn make CFLAGS_EXTRA=-DDEBUG release_embed
    expect "New password:"
    send -- "$PASS\r"
    expect eof
EOF

expect <<EOF
    log_user 1
    exp_internal 1
    set timeout -1
    spawn sudo ./build/launch
    expect -re "(?i)password.*:"
    send -- "$SUDOPASS\r"
    sleep 1
    send -- "$PASS\r"
    sleep 1
    send -- "$ARGS\r"
    expect
EOF