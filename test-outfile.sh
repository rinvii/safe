#!/bin/bash
set -euo pipefail

SUDOPASS=""
PASS="hello"
ARGS=""

rm -f out.enc out plain

make clean
make all

expect <<EOF
    spawn make CFLAGS_EXTRA=-DDEBUG release_embed
    expect "New password:"
    send "$PASS\r"
    expect eof
EOF

expect <<EOF
    spawn sudo ./build/launch --out out.enc
    expect -re "(?i)password.*:"
    send -- "$SUDOPASS\r"
    sleep 1
    send -- "$PASS\r"
    sleep 1
    send -- "$ARGS\r"
    expect eof
EOF

expect <<EOF
    spawn sudo chmod +r out.enc
    expect -re "(?i)password.*:"
    send "$SUDOPASS\r"
    expect eof
EOF

expect <<EOF
    spawn ./build/decrypt out.enc plain
    expect "Password:"
    send "$PASS\r"
    expect eof
EOF

cat plain