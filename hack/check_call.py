#!/usr/bin/env python3
"""Asserts what a captured SIPp call has to look like. Used by hack/real-call.sh.

    hack/check_call.py CAPTURE --rq ./rtp-quality --uac-rtp 6144 --uas-rtp 7168 --mode clean|impaired

clean:    both streams complete, nothing lost, jitter small, good MOS.
impaired: netem took 8 % of the media packets in each direction (and added delay with
          jitter), so loss and jitter must be visible and MOS must have dropped. The echo
          stream carries the first leg's gaps in its sequence numbers as well, so it shows
          roughly 1 - 0.92^2 = 15 % loss. The bounds are wide because 500 packets is a small sample.
"""
import argparse
import json
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--rq", default="./rtp-quality")
    ap.add_argument("--uac-rtp", type=int, default=6144)
    ap.add_argument("--uas-rtp", type=int, default=7168)
    ap.add_argument("--mode", choices=["clean", "impaired"], required=True)
    args = ap.parse_args()

    out = subprocess.run([args.rq, "-format", "json", args.capture], capture_output=True, text=True, check=True).stdout
    streams = json.loads(out)["streams"]
    problems = []

    def find(first_port):
        # SIPp takes the media port from a 16-port range starting here
        found = [s for s in streams if first_port <= int(s["dst"].rsplit(":", 1)[1]) < first_port + 16]
        if len(found) != 1:
            problems.append(f"expected one stream towards ports {first_port}-{first_port + 15}, found {len(found)}")
            return None
        return found[0]

    forward = find(args.uas_rtp)  # caller -> callee
    echo = find(args.uac_rtp)  # callee -> caller
    for name, s in (("caller to callee", forward), ("echo back", echo)):
        if s is None:
            continue
        print(f"{name}: {s['codec']} {s['packets']}/{s['expected']} packets, loss {s['loss_percent']} %, "
              f"jitter {s['jitter_mean_ms']} ms, MOS {s['mos']}")
        if s["codec"] != "PCMA":
            problems.append(f"{name}: codec {s['codec']}, expected PCMA")
        if s["expected"] < 480 or s["expected"] > 520:
            problems.append(f"{name}: {s['expected']} packets expected over ten seconds of 20 ms audio")

    if forward and echo:
        if args.mode == "clean":
            if forward["lost"] != 0:
                problems.append(f"caller to callee lost {forward['lost']} packets on loopback")
            if echo["loss_percent"] > 1:
                problems.append(f"echo lost {echo['loss_percent']} % on loopback")
            for name, s in (("caller to callee", forward), ("echo", echo)):
                if s["jitter_mean_ms"] > 10:
                    problems.append(f"{name}: mean jitter {s['jitter_mean_ms']} ms on loopback")
                if s["mos"] is None or s["mos"] < 4.0:
                    problems.append(f"{name}: MOS {s['mos']}")
        else:
            if not 2 <= forward["loss_percent"] <= 16:
                problems.append(f"caller to callee: loss {forward['loss_percent']} %, netem was set to 8 %")
            if not 5 <= echo["loss_percent"] <= 30:
                problems.append(f"echo: loss {echo['loss_percent']} %, expected about 15 %")
            for name, s in (("caller to callee", forward), ("echo", echo)):
                if s["jitter_mean_ms"] < 1.5:
                    problems.append(f"{name}: mean jitter {s['jitter_mean_ms']} ms, netem adds +/-10 ms")
                if s["mos"] is None or s["mos"] > 4.3:
                    problems.append(f"{name}: MOS {s['mos']} is too good for a network that drops 8 %")
            if echo["mos"] is not None and forward["mos"] is not None and echo["mos"] >= forward["mos"]:
                problems.append("the echo, which crossed the bad network twice, should not score better than the first leg")

    for p in problems:
        print("FAIL:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
