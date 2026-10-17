#!/usr/bin/env bash
# One real call on the loopback interface, measured two ways.
#
#   SIPp (caller) --play_pcap_audio--> SIPp (callee, -rtp_echo) --> back to the caller
#
# tcpdump records the call, rtp-quality analyzes the capture and tshark checks it.
# Needs root (raw sockets for play_pcap_audio, packet capture, tc), sipp, tcpdump, tshark,
# python3. With NETEM=1 the media - and only the media - gets 15 ms +/- 10 ms of delay and
# 8 % loss from the kernel's netem, and the checks expect to see it.
#
#   sudo RQ=./rtp-quality hack/real-call.sh          # a clean call
#   sudo NETEM=1 RQ=./rtp-quality hack/real-call.sh  # the same call over a bad network
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
RQ="${RQ:-./rtp-quality}"
NETEM="${NETEM:-0}"
work="$(mktemp -d)"
# SIPp picks the media port from a range; 16-port ranges on a 16-port boundary let one
# netem filter mask cover each of them.
UAC_SIP=5060 UAC_RTP=6144 UAS_SIP=5070 UAS_RTP=7168

cleanup() {
  [ -n "${tcpdump_pid:-}" ] && kill "$tcpdump_pid" 2>/dev/null || true
  [ -n "${uas_pid:-}" ] && kill "$uas_pid" 2>/dev/null || true
  tc qdisc del dev lo root 2>/dev/null || true
}
trap cleanup EXIT

# Ten seconds of caller audio for SIPp to play.
"$RQ" gen -oneway -codec PCMA -duration 10 -o "$work/call.pcap"

if [ "$NETEM" = 1 ]; then
  modprobe sch_prio sch_netem cls_u32 2>/dev/null || true
  # A priority qdisc whose third band is a netem; a filter sends only the two media ports there,
  # so SIP is not touched and the call still sets up.
  tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
  tc qdisc add dev lo parent 1:3 handle 30: netem delay 15ms 10ms loss 8%
  for port in "$UAC_RTP" "$UAS_RTP"; do
    tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip dport "$port" 0xfff0 flowid 1:3
  done
  tc qdisc show dev lo
fi

# SIPp 3.7 takes a media port range, 3.6 (Ubuntu 22.04) a single port; both end up inside the
# 16 ports the netem filter and check_call.py expect.
sipp_help="$(sipp -h 2>&1 || true)"
if grep -q -- '-min_rtp_port' <<<"$sipp_help"; then
  rtp_ports() { echo "-min_rtp_port $1 -max_rtp_port $(($1 + 15))"; }
else
  rtp_ports() { echo "-mp $1"; }
fi

capture="$work/call-capture.pcap"
tcpdump -i lo -U -n -w "$capture" udp 2>"$work/tcpdump.log" &
tcpdump_pid=$!
for _ in $(seq 50); do [ "$(stat -c %s "$capture" 2>/dev/null || echo 0)" -ge 24 ] && break; sleep 0.1; done

sipp -sf "$here/uas_echo.xml" -i 127.0.0.1 -p "$UAS_SIP" $(rtp_ports "$UAS_RTP") -rtp_echo -m 1 -nostdin \
  -trace_err -error_file "$work/uas_err.log" >"$work/uas.log" 2>&1 &
uas_pid=$!
sleep 1

(cd "$work" && sipp -sf "$here/uac_audio.xml" -s 2000 -i 127.0.0.1 -p "$UAC_SIP" $(rtp_ports "$UAC_RTP") -m 1 -nostdin \
  -timeout 60 -timeout_error -trace_err -error_file "$work/uac_err.log" "127.0.0.1:$UAS_SIP") >"$work/uac.log" 2>&1 \
  || { echo "SIPp caller failed"; tail -30 "$work/uac.log"; cat "$work"/uac_err.log 2>/dev/null; exit 1; }
wait "$uas_pid" || { echo "SIPp callee failed"; tail -30 "$work/uas.log"; exit 1; }
uas_pid=""

sleep 1
kill -INT "$tcpdump_pid"; wait "$tcpdump_pid" 2>/dev/null || true; tcpdump_pid=""
cat "$work/tcpdump.log"

"$RQ" "$capture"
python3 "$here/check_call.py" --rq "$RQ" --uac-rtp "$UAC_RTP" --uas-rtp "$UAS_RTP" \
  --mode "$([ "$NETEM" = 1 ] && echo impaired || echo clean)" "$capture"
python3 "$here/crosscheck.py" --rq "$RQ" --sip-port "$UAS_SIP" "$capture"
echo "capture kept in $work"
