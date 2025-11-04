#!/bin/bash
set -euo pipefail

PASS=""
ARGS=""
SUDOPASS=""

# ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password user@host
TARGET="user@localhost

if ssh "$TARGET" 'test -e /dev/shm/lab3-print'; then
    echo "ERROR: /dev/shm/lab3-print already exists on $TARGET — aborting."
    exit 1
fi

scp lab3-draw $TARGET:/dev/shm/lab3-draw

expect <<EOF
    spawn ssh -t $TARGET "chmod +x /dev/shm/lab3-draw && sudo /dev/shm/lab3-draw --out /dev/shm/lab3-print && sleep 3 && sudo chmod 644 /dev/shm/lab3-print && rm /dev/shm/lab3-draw"
    # expect -re "(?i)password.*:"
    # send -- "$SUDOPASS\r"
    sleep 10
    send -- "$PASS\r"
    sleep 10
    send -- "$ARGS\r"
    expect eof
EOF