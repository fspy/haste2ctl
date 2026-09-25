#!/usr/bin/env python3
"""
Unit tests for the pure helpers in haste2ctl.py - no device needed.

These cover the arithmetic that the CLI golden test deliberately normalises
away (stage codes, divisor mapping, masks, argument parsing), plus the
protocol encodings verified against the real mouse earlier.

    ./test_units.py
"""

import argparse
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
    "h", pathlib.Path(__file__).parent / "haste2ctl.py"
)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

FAILS = []


def check(label, got, want):
    if got != want:
        FAILS.append(f"{label}: got {got!r}, want {want!r}")


def check_raises(label, fn, *a, **kw):
    """Assert fn rejects the input. `kind` defaults to DevError."""
    kind = kw.pop("kind", h.DevError)
    try:
        fn(*a, **kw)
    except kind:
        return
    except Exception as e:  # wrong exception type is still a failure
        FAILS.append(f"{label}: raised {type(e).__name__}, want {kind.__name__}")
        return
    FAILS.append(f"{label}: did not raise")


# -- DPI code round trip: code = DPI/50 - 1 -------------------------------
# Verified on hardware: 400->0x0007, 3200->0x003F, 26000->0x0207, 5550->0x006E
for dpi, code in (
    (50, 0x0000),
    (400, 0x0007),
    (800, 0x000F),
    (1200, 0x0017),
    (1600, 0x001F),
    (2000, 0x0027),
    (3200, 0x003F),
    (5550, 0x006E),
    (13000, 0x0103),
    (26000, 0x0207),
):
    check(f"encode_dpi({dpi})", h.encode_dpi(dpi), code)
    check(f"decode_dpi(0x{code:04X})", h.decode_dpi(code), dpi)

check_raises("encode_dpi rejects 1234 (not a multiple of 50)", h.encode_dpi, 1234)
check_raises("encode_dpi rejects 0 (below min)", h.encode_dpi, 0)
check_raises("encode_dpi rejects 26050 (above max)", h.encode_dpi, 26050)
check_raises("encode_dpi rejects 26100", h.encode_dpi, 26100)

# -- polling divisors: Hz = 8000 / RR --------------------------------------
for hz, rr in (
    (125, 0x40),
    (250, 0x20),
    (500, 0x10),
    (1000, 0x08),
    (2000, 0x04),
    (4000, 0x02),
    (8000, 0x01),
):
    check(f"poll_rate_to_divisor({hz})", h.poll_rate_to_divisor(hz), rr)
    check(f"divisor_to_poll_rate(0x{rr:02X})", h.divisor_to_poll_rate(rr), hz)

check("divisor_to_poll_rate(0) is not a real rate", h.divisor_to_poll_rate(0), 0)
check_raises("poll_rate_to_divisor rejects 999", h.poll_rate_to_divisor, 999)
check_raises("poll_rate_to_divisor rejects 16000", h.poll_rate_to_divisor, 16000)

# -- stage masks ----------------------------------------------------------
check("mask_for_stage_count(4)", h.mask_for_stage_count(4), 0x0F)
check("mask_for_stage_count(5)", h.mask_for_stage_count(5), 0x1F)
check_raises("mask_for_stage_count rejects 3", h.mask_for_stage_count, 3)
check_raises("mask_for_stage_count rejects 6", h.mask_for_stage_count, 6)

# -- stage offsets --------------------------------------------------------
check("stage_offset(0)", h.stage_offset(0), 5)
check("stage_offset(4)", h.stage_offset(4), 25)
check_raises("stage_offset rejects 5", h.stage_offset, 5)
check_raises("stage_offset rejects -1", h.stage_offset, -1)

# -- stage field access against a real captured reply ---------------------
# The 64-byte 33 02 reply read from the mouse, written out field by field so
# the expected values are legible rather than buried in a hex blob.
REAL_REPLY = bytes(
    [0x33, 0x02, 0x01, 0x0F, 0x02]  # RR=0x01 (8000 Hz), mask=0x0F, active=2
    + [0x07, 0x00, 0xFF, 0x00, 0x00]  # stage 0: 400 DPI,   red
    + [0x0F, 0x00, 0x00, 0x00, 0xFF]  # stage 1: 800 DPI,   blue
    + [0x1F, 0x00, 0xFF, 0xFF, 0x00]  # stage 2: 1600 DPI,  yellow
    + [0x3F, 0x00, 0x00, 0xFF, 0x00]  # stage 3: 3200 DPI,  green
    + [0x00, 0x00, 0x00, 0x00, 0x00]  # stage 4: unused
).ljust(64, b"\x00")
check("real reply length", len(REAL_REPLY), 64)
for stage, (dpi, rgb) in enumerate(
    (
        (400, (0xFF, 0, 0)),
        (800, (0, 0, 0xFF)),
        (1600, (0xFF, 0xFF, 0)),
        (3200, (0, 0xFF, 0)),
    )
):
    check(
        f"real reply stage {stage} dpi",
        h.decode_dpi(h.read_stage_code(REAL_REPLY, stage)),
        dpi,
    )
    check(f"real reply stage {stage} colour", h.stage_colour(REAL_REPLY, stage), rgb)
check("real reply active stage", REAL_REPLY[h.ACTIVE_STAGE_OFFSET], 2)
check("real reply mask", REAL_REPLY[h.STAGE_MASK_OFFSET], 0x0F)
check("real reply enabled count", h._enabled_stage_count(REAL_REPLY), 4)

# -- resolve_stage --------------------------------------------------------
check("resolve_stage(None)", h.resolve_stage(None, REAL_REPLY), None)
check("resolve_stage('2')", h.resolve_stage("2", REAL_REPLY), 2)
check("resolve_stage('current')", h.resolve_stage("current", REAL_REPLY), 2)
check("resolve_stage('ACTIVE')", h.resolve_stage("ACTIVE", REAL_REPLY), 2)
check_raises("resolve_stage rejects 'bogus'", h.resolve_stage, "bogus", REAL_REPLY)
check_raises("resolve_stage rejects '4.5'", h.resolve_stage, "4.5", REAL_REPLY)

# A reply whose active stage is disabled must be rejected, not silently used.
DISABLED_ACTIVE = bytearray(REAL_REPLY)
DISABLED_ACTIVE[h.ACTIVE_STAGE_OFFSET] = 4  # stage 4 is masked off
check_raises(
    "resolve_stage rejects a disabled active stage",
    h.resolve_stage,
    "current",
    bytes(DISABLED_ACTIVE),
)

# -- colour parsing -------------------------------------------------------
for text, want in (
    ("red", (255, 0, 0)),
    ("lime", (0, 255, 0)),
    ("off", (0, 0, 0)),
    ("on", (255, 255, 255)),
    ("f00", (255, 0, 0)),
    ("F00", (255, 0, 0)),
    ("#ff8800", (255, 136, 0)),
    ("00FF00", (0, 255, 0)),
    ("ff0000", (255, 0, 0)),
):
    check(f"parse_rgb({text!r})", h.parse_rgb(text), want)
for bad in ("nothex", "", "#12", "12345", "gggggg"):
    # parse_rgb is an argparse type function, so ArgumentTypeError is correct.
    check_raises(
        f"parse_rgb rejects {bad!r}", h.parse_rgb, bad, kind=argparse.ArgumentTypeError
    )

# -- light target disambiguation -----------------------------------------
# A bare integer is always brightness; a colour needs a '#' or a name.
for text, kind, want in (
    ("0", "level", 0),
    ("128", "level", 128),
    ("255", "level", 255),
    ("on", "level", 255),
    ("off", "level", 0),
    ("OFF", "level", 0),
    (" 128 ", "level", 128),
    ("#ff8800", "color", (255, 136, 0)),
    ("#123456", "color", (0x12, 0x34, 0x56)),
    ("f00", "color", (255, 0, 0)),
    ("red", "color", (255, 0, 0)),
    ("lime", "color", (0, 255, 0)),
):
    check(f"parse_light_target({text!r})", h.parse_light_target(text), (kind, want))

# Out-of-range numbers must be refused, not guessed at as colours.
for bad in ("300", "9999", "-5", "123456", "nothex"):
    check_raises(f"parse_light_target rejects {bad!r}", h.parse_light_target, bad)
# The '#'-colour hint is only offered where it would actually parse.
check(
    "hex hint for 6 digits",
    h._hex_hint("123456").startswith(" If you meant the colour #123456"),
    True,
)
check(
    "hex hint for 3 digits",
    h._hex_hint("300").startswith(" If you meant the colour #300"),
    True,
)
check("no hex hint for 4 digits", h._hex_hint("9999"), "")
check("no hex hint for a negative", h._hex_hint("-5"), "")

# -- interface selection strategies ---------------------------------------
IFACES = [
    {"node": "/dev/hidraw1", "iface": 0, "rdesc": 94},
    {"node": "/dev/hidraw2", "iface": 1, "rdesc": 93},
    {"node": "/dev/hidraw3", "iface": 2, "rdesc": 598},
]
check("select_vendor picks interface 2", h.select_vendor(IFACES)[0], "/dev/hidraw3")
# No interface number to go on: fall back to the only non-boot one.
NO_NUMBER = [{"node": "/dev/hidraw9", "iface": None, "rdesc": 598}] + IFACES[:2]
check(
    "select_vendor falls back to the sole non-boot interface",
    h.select_vendor(NO_NUMBER)[0],
    "/dev/hidraw9",
)
check(
    "select_vendor returns None when nothing matches", h.select_vendor(IFACES[:2]), None
)
check("select_vendor returns None for no interfaces", h.select_vendor([]), None)

# -- report assembly ------------------------------------------------------
# A live write is 32 01 00 00 followed by the queried table, header swapped.
check(
    "write_config header",
    bytes([0x32, 0x01, 0x00, 0x00]) + REAL_REPLY[2:62][:8],
    bytes.fromhex("32010000") + REAL_REPLY[2:10],
)

if FAILS:
    print(f"FAIL  {len(FAILS)} of {len(FAILS)} checks failed")
    for f in FAILS:
        print(f"  - {f}")
    sys.exit(1)
print("OK  all unit checks passed")
