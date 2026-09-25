#!/usr/bin/env python3
"""
The diff behind the README's claim that the two shipped captures are the
same traffic.

`turned_lights_on.pcapng` and `turned_lights_off.pcapng` turn out to contain
byte-identical USB payloads - both are the "lights off" state. The packet
counts differ only because the captures ran for different lengths of time.

This compares the *set* of distinct (endpoint, payload) pairs rather than the
sequence, then also checks the common prefix positionally, because a
one-capture-longer comparison would otherwise hide a divergence that only
exists past the shorter file's end.

    tools/pcap_diff.py turned_lights_on.pcapng turned_lights_off.pcapng
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_summary import load, read_pcapng, parse_usb, key_of  # noqa: E402


def payload_sequence(path):
    """Non-empty interrupt transfers, in order, for the mouse's endpoints."""
    out = []
    for _, _, raw in read_pcapng(path):
        u = parse_usb(raw)
        if not u or u["xfer"] != 1:  # interrupt endpoints only
            continue
        data = bytes(u["data"])
        if data:  # skip zero-length status URBs
            out.append(key_of(u))
    return out


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    a_path, b_path = argv[1], argv[2]

    _, a_pl, a_frames, a_excess = load(a_path)
    _, b_pl, b_frames, b_excess = load(b_path)
    a_keys, b_keys = set(a_pl), set(b_pl)

    print(f"{a_path}\n  {a_frames} packets, {a_excess} unparsed, "
          f"{len(a_keys)} unique (endpoint,payload) pairs")
    print(f"{b_path}\n  {b_frames} packets, {b_excess} unparsed, "
          f"{len(b_keys)} unique (endpoint,payload) pairs\n")

    only_a = a_keys - b_keys
    only_b = b_keys - a_keys
    for label, keys in (("only in A", only_a), ("only in B", only_b)):
        if not keys:
            print(f"  {label}: 0")
            continue
        print(f"  {label}: {len(keys)}")
        for key, data in sorted(keys)[:20]:
            print(f"    {key[4]} ep{key[2]:#04x} {data.hex()[:72]}")
    print(f"\n  payload sets identical: {a_keys == b_keys}")

    a_seq, b_seq = payload_sequence(a_path), payload_sequence(b_path)
    common = min(len(a_seq), len(b_seq))
    first_diff = next((i for i in range(common) if a_seq[i] != b_seq[i]), None)
    print(f"\n  positional: A has {len(a_seq)} transfers, B has {len(b_seq)}; "
          f"comparing {common}")
    if first_diff is None:
        print("  IDENTICAL for the whole common prefix")
    else:
        print(f"  first divergence at index {first_diff}:")
        print(f"    A {a_seq[first_diff][0]} {a_seq[first_diff][1].hex()[:72]}")
        print(f"    B {b_seq[first_diff][0]} {b_seq[first_diff][1].hex()[:72]}")

    outs_a = {k[1] for k in a_pl if k[0][4] == "OUT" and k[1]}
    outs_b = {k[1] for k in b_pl if k[0][4] == "OUT" and k[1]}
    print("\n  distinct host->device commands:")
    print(f"    A: {[d.hex()[:12] for d in sorted(outs_a)]}")
    print(f"    B: {[d.hex()[:12] for d in sorted(outs_b)]}")
    return 0 if a_keys == b_keys and first_diff is None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
