#!/usr/bin/env python3
"""
Minimal pcapng + USBPcap2 reader, and the diff that settles a question about
the two captures shipped in this repo.

No dependencies - just struct. The USBPcap2 pseudo-header is 27 bytes:

    [0:3]    flags / constant
    [3:11]   u64 irpId
    [11:14]  status
    [14:16]  u16 urbFunction
    [17]     u8  bus
    [19]     u8  deviceAddress
    [21]     u8  endpoint
    [22]     u8  transferType
    [23:27]  u32 dataLength

CONTROL transfers carry a 1-byte dataFlag before the 8-byte setup packet, so
their header is 28 bytes. Wireshark's own `usbpcap pseudoheader length` field
disagrees between the two cases (27 vs 28) depending on whether it counts that
flag - this parser derives the offset from the transfer type instead.

Usage:
    tools/pcap_summary.py <capture.pcapng> [...]
    tools/pcap_diff.py <a.pcapng> <b.pcapng>
"""

import collections
import struct
import sys

HDR = 27
REPORT_LEN = 64
ACK = 0xFF
XFERS = {0: "ISO", 1: "INTERRUPT", 2: "CONTROL", 3: "BULK"}


class CaptureError(Exception):
    pass


def read_pcapng(path):
    """Yield (frame_number, timestamp, raw_bytes) for each packet block."""
    with open(path, "rb") as fh:
        data = fh.read()
    off, endian, n = 0, "<", 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        if btype == 0x0A0D0D0A:  # Section Header: re-derive endianness
            if struct.unpack_from("<I", data, off + 8)[0] == 0x1A2B3C4D:
                endian = "<"
            else:
                endian = ">"
            btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000006:  # Enhanced Packet Block
            _, ts_hi, ts_lo, caplen, _ = struct.unpack_from(
                endian + "IIIII", body, 0)
            n += 1
            yield n, (ts_hi << 32) | ts_lo, body[20:20 + caplen]
        off += blen


def parse_usb(pkt):
    """Decode one USBPcap2 pseudo-header, or None if too short."""
    if len(pkt) < HDR:
        return None
    function = struct.unpack_from("<H", pkt, 14)[0]
    bus, dev, ep, xfer = pkt[17], pkt[19], pkt[21], pkt[22]
    dlen = struct.unpack_from("<I", pkt, 23)[0]
    off = HDR + (1 if xfer == 2 else 0)  # control transfers have a dataFlag
    return {
        "function": function,
        "bus": bus,
        "dev": dev,
        "ep": ep,
        "xfer": xfer,
        "data": pkt[off:off + dlen],
        # Anything left over means the header layout assumption is wrong.
        "excess": len(pkt) - (off + dlen),
    }


def key_of(u):
    """Identity of a transfer for comparison: where it went, and its bytes."""
    direction = "IN" if (u["ep"] & 0x80) else "OUT"
    return (u["bus"], u["dev"], u["ep"], XFERS.get(u["xfer"], u["xfer"]),
            direction), bytes(u["data"])


def load(path):
    """Return (counts, payload_counts, total_frames, unparsed_bytes)."""
    counts = collections.Counter()
    payloads = collections.Counter()
    frames = excess = 0
    for _, _, raw in read_pcapng(path):
        u = parse_usb(raw)
        if not u:
            continue
        frames += 1
        excess += u["excess"]
        key, data = key_of(u)
        counts[key] += 1
        payloads[(key, data)] += 1
    return counts, payloads, frames, excess


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for path in argv[1:]:
        counts, payloads, frames, excess = load(path)
        print(f"=== {path}: {frames} packets, "
              f"{excess} unparsed trailing bytes ===")
        for key, n in sorted(counts.items()):
            print(f"  bus{key[0]}.dev{key[1]}.ep{key[2]:#04x} "
                  f"{key[3]:9s} {key[4]:3s} {n:5d}")
        print(f"  -> {len(payloads)} unique payloads\n")
        for (key, data), n in sorted(payloads.items(),
                                      key=lambda kv: -kv[1])[:12]:
            print(f"  [{n:5d}x] {key[4]:3s} ep{key[2]:#04x} "
                  f"len={len(data):3d} {data.hex()[:72]}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
