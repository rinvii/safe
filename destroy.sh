#!/usr/bin/env bash

PASS=""

declare -A SOURCES=(
  [self]="user@localhost"
)

declare -a PIDS=()

show_output() {
  local name=$1
  local file="$name"
  echo "--- $name ---"

  if [[ ! -f "$file" ]]; then
    echo "(missing)"
    return
  fi

  local tmp="${file}.$$.tmp"
  # keep only first two lines
  awk 'NR<=2{print}' "$file" > "$tmp" 2>/dev/null || { rm -f "$tmp"; echo "(read error)"; return; }

  # atomically replace original file with truncated version
  mv -f "$tmp" "$file" || { rm -f "$tmp"; echo "(mv error)"; return; }

  # print the remaining (first two) lines
  sed -n '1,2p' "$file"

  # extract PID(s) from these lines, append as "name:pid" to PIDS[]
  # handle forms like "current pid:613500" with flexible whitespace
  while IFS= read -r line; do
    # normalize line to lowercase for matching
    lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
    if [[ $lower =~ current[[:space:]]*pid[[:space:]]*[:]*[[:space:]]*([0-9]+) ]]; then
      pid="${BASH_REMATCH[1]}"
      userhost=${SOURCES[$name]%%:*}
      [[ -n $pid ]] && PIDS+=("${userhost}=${pid}")
    fi
  done < <(sed -n '1,2p' "$file")
}

for name in "${!SOURCES[@]}"; do
show_output "$name"
done

# print collected PIDs at end of cycle
if (( ${#PIDS[@]} > 0 )); then
echo "=== Collected PIDs this cycle ==="
printf '%s\n' "${PIDS[@]}"
else
echo "No PIDs found this cycle."
fi

for entry in "${PIDS[@]}"; do
    lhs="${entry%%=*}"
    rhs="${entry#*=}"
    expect <<EOF
log_user 1
spawn ssh -t $lhs "sudo kill -9 $rhs && sudo rm /dev/shm/lab3-print"
expect -re "(?i)password.*:"
send -- "$PASS\r"
expect eof
EOF
dones