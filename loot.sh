#!/bin/bash
set -euo pipefail

PASS=""           # decryption passphrase
# BASE=60         # base sleep (s)
# JITTER=30       # random jitter (s)

# key = short name, value = scp source (user@host:path)
declare -A SOURCES=(
  [self]="user@localhost:/dev/shm/lab3-print"
)

download_file() {
  local name=$1
  local src=${SOURCES[$name]}
  local dest="${name}.enc"
  echo "Downloading $name..."
  scp -q "$src" "$dest"
}

decrypt_file() {
  local infile=$1
  local outfile=$2
  echo "Decrypting $infile -> $outfile"
  expect <<EOF >/dev/null
    set timeout 10
    spawn ./build/decrypt $infile $outfile
    expect "Password:"
    send -- "$PASS\r"
    expect eof
EOF
}

show_output() {
  local name=$1
  echo "--- $name ---"
  cat "$name" 2>/dev/null || echo "(missing)"
}

# random_sleep() {
#   local delta=$(( RANDOM % (2 * JITTER + 1) - JITTER ))
#   local s=$(( BASE + delta ))
#   (( s < 1 )) && s=1
#   echo "Sleeping ${s}s"
#   sleep "$s"
# }

# while true; do
  # echo "=== $(date '+%F %T') ==="

for name in "${!SOURCES[@]}"; do
  download_file "$name"
done

for name in "${!SOURCES[@]}"; do
  decrypt_file "${name}.enc" "$name"
done

for name in "${!SOURCES[@]}"; do
  show_output "$name"
done

#   random_sleep
# done
