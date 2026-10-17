#!/usr/bin/env python3
"""Compares rtp-quality with Wireshark's RTP analysis of the same capture.

    hack/crosscheck.py CAPTURE [--rq ./rtp-quality] [--sip-port 5070]

Both tools read the same file, so any disagreement is a bug in one of them. The
two count a few things differently on purpose, and the comparison accounts for it:

  * tshark's "Lost" is expected minus packets received *including duplicates*, so a
    duplicate hides a loss. rtp-quality counts distinct packets.
  * tshark's mean jitter is the average of the running RFC 3550 estimate, the same
    quantity rtp-quality reports as its mean; small differences come from how a
    stream's first packets and marker-bit packets are treated.

Exit status is 0 when every stream agrees, 1 otherwise. Standard library only.
"""
import argparse
import json
import re
import subprocess
import sys

ROW = re.compile(
    r"^\s*(?P<start>[\d.]+)\s+(?P<end>[\d.]+)\s+(?P<src>\S+)\s+(?P<sport>\d+)\s+(?P<dst>\S+)\s+(?P<dport>\d+)\s+"
    r"(?P<ssrc>0x[0-9A-Fa-f]+)\s+(?P<payload>.+?)\s+(?P<pkts>\d+)\s+(?P<lost>-?\d+)\s+\((?P<lostpct>-?[\d.]+)%\)\s+"
    r"(?P<mind>[\d.]+)\s+(?P<meand>[\d.]+)\s+(?P<maxd>[\d.]+)\s+"
    r"(?P<minj>[\d.]+)\s+(?P<meanj>[\d.]+)\s+(?P<maxj>[\d.]+)"
)


def tshark_streams(capture, sip_port):
    cmd = ["tshark", "-r", capture, "-o", "rtp.heuristic_rtp:TRUE", "-q", "-z", "rtp,streams"]
    if sip_port:
        cmd[3:3] = ["-d", f"udp.port=={sip_port},sip"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        m = ROW.match(line)
        if m:
            rows[(int(m["ssrc"], 16), int(m["sport"]), int(m["dport"]))] = m.groupdict()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--rq", default="./rtp-quality")
    ap.add_argument("--sip-port", default="")
    ap.add_argument("--jitter-tolerance-ms", type=float, default=1.5)
    args = ap.parse_args()

    ours = json.loads(subprocess.run([args.rq, "-format", "json", "-min-packets", "1", args.capture],
                                     capture_output=True, text=True, check=True).stdout)
    theirs = tshark_streams(args.capture, args.sip_port)

    problems = []
    print(f"{'ssrc':<12}{'':<3}{'packets':>14}{'lost':>14}{'mean jitter ms':>22}")
    for s in ours["streams"]:
        # the same SSRC can appear in both directions (an echo keeps it), so the ports are part of the key
        key = (int(s["ssrc"], 16), int(s["src"].rsplit(":", 1)[1]), int(s["dst"].rsplit(":", 1)[1]))
        t = theirs.pop(key, None)
        if t is None:
            problems.append(f"{s['ssrc']} {s['src']} -> {s['dst']}: rtp-quality found a stream that tshark did not")
            continue
        received = s["packets"] + s["duplicates"]  # what tshark calls Pkts
        lost_tshark = s["expected"] - received
        pk, lo, jit = int(t["pkts"]), int(t["lost"]), float(t["meanj"])
        print(f"{s['ssrc']:<12}rq {received:>14}{lost_tshark:>14}{s['jitter_mean_ms']:>22.2f}")
        print(f"{'':<12}ws {pk:>14}{lo:>14}{jit:>22.2f}")
        if pk != received:
            problems.append(f"{s['ssrc']}: packets {received} (rtp-quality) vs {pk} (tshark)")
        if abs(lo - lost_tshark) > 1:
            problems.append(f"{s['ssrc']}: lost {lost_tshark} (rtp-quality, duplicates counted as tshark does) vs {lo} (tshark)")
        if abs(jit - s["jitter_mean_ms"]) > max(args.jitter_tolerance_ms, 0.25 * jit):
            problems.append(f"{s['ssrc']}: mean jitter {s['jitter_mean_ms']:.2f} ms vs {jit:.2f} ms (tshark)")
    for ssrc, sport, dport in theirs:
        problems.append(f"0x{ssrc:08x} {sport}->{dport}: tshark found a stream that rtp-quality did not")
    if not ours["streams"]:
        problems.append("no streams found")
    for p in problems:
        print("MISMATCH:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
