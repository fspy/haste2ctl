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


MAX_SHOWN = 20
HEX_PREVIEW = 72


def _print_file_header(path, pl, frames, excess):
    print(f"{path}\n  {frames} packets, {excess} unparsed, "
          f"{len(set(pl))} unique (endpoint,payload) pairs")


def _print_only(label, keys):
    if not keys:
        print(f"  {label}: 0")
        return
    print(f"  {label}: {len(keys)}")
    for key, data in sorted(keys)[:MAX_SHOWN]:
        print(f"    {key[4]} ep{key[2]:#04x} {data.hex()[:HEX_PREVIEW]}")


def _first_divergence(a_seq, b_seq):
    """Index of the first differing transfer within the common prefix."""
    common = min(len(a_seq), len(b_seq))
    return next((i for i in range(common) if a_seq[i] != b_seq[i]), None)


def _print_positional(a_path, b_path):
    a_seq, b_seq = payload_sequence(a_path), payload_sequence(b_path)
    common = min(len(a_seq), len(b_seq))
    first = _first_divergence(a_seq, b_seq)
    print(f"\n  positional: A has {len(a_seq)} transfers, B has {len(b_seq)}; "
          f"comparing {common}")
    if first is None:
        print("  IDENTICAL for the whole common prefix")
    else:
        print(f"  first divergence at index {first}:")
        for label, seq in (("A", a_seq), ("B", b_seq)):
            key, data = seq[first]
            print(f"    {label} {key} {data.hex()[:HEX_PREVIEW]}")


def _host_commands(payloads):
    return {k[1] for k in payloads if k[0][4] == "OUT" and k[1]}


def _print_commands(a_pl, b_pl):
    print("\n  distinct host->device commands:")
    for label, pl in (("A", a_pl), ("B", b_pl)):
        print(f"    {label}: {[d.hex()[:12] for d in sorted(_host_commands(pl))]}")


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    a_path, b_path = argv[1], argv[2]

    _, a_pl, a_frames, a_excess = load(a_path)
    _, b_pl, b_frames, b_excess = load(b_path)
    a_keys, b_keys = set(a_pl), set(b_pl)

    _print_file_header(a_path, a_pl, a_frames, a_excess)
    _print_file_header(b_path, b_pl, b_frames, b_excess)
    print()
    _print_only("only in A", a_keys - b_keys)
    _print_only("only in B", b_keys - a_keys)
    print(f"\n  payload sets identical: {a_keys == b_keys}")

    _print_positional(a_path, b_path)
    _print_commands(a_pl, b_pl)

    identical = a_keys == b_keys
    positional_ok = _first_divergence(payload_sequence(a_path),
                                      payload_sequence(b_path)) is None
    return 0 if identical and positional_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
