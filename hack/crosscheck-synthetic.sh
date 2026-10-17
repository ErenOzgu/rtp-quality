#!/usr/bin/env bash
# Generates calls with known impairments and checks rtp-quality against tshark on each.
#   RQ=./rtp-quality hack/crosscheck-synthetic.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
RQ="${RQ:-./rtp-quality}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

i=0
# clean, random loss, bursty loss, heavy jitter with reordering, duplicates and DTMF, G.729, pcapng
for args in \
  "-duration 20" \
  "-duration 40 -loss 4 -both" \
  "-duration 40 -loss 6 -burst 4 -both" \
  "-duration 40 -jitter 45 -reorder 3 -dup 2 -both" \
  "-duration 30 -loss 3 -jitter 20 -dtmf 2,7,12 -both" \
  "-duration 30 -codec G729 -ptime 20 -loss 2 -jitter 15 -both" \
  "-duration 30 -format pcapng -nano -loss 3 -jitter 25 -both"; do
  i=$((i + 1))
  echo "=== call $i: $args"
  # shellcheck disable=SC2086
  "$RQ" gen -seed "$i" $args -o "$work/call$i.pcap"
  python3 "$here/crosscheck.py" --rq "$RQ" "$work/call$i.pcap"
done
