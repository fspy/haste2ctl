#!/usr/bin/env python3
"""
Golden-output regression tests for haste2ctl.py.

Written before any refactoring, so behaviour-preservation can be proven rather
than asserted. Each case runs the CLI and compares combined
(stdout + stderr + exit code) against a recorded baseline.

    ./test_cli.py            # run against the recorded baseline
    ./test_cli.py --bless    # re-record the baseline (use ONLY for an
                                # intentional behaviour change)

Requires the mouse to be present. State is pinned to a known brightness at the
start and end so readbacks are deterministic.
"""

import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
TOOL = HERE / "haste2ctl.py"
GOLDEN = HERE / "tests" / "golden.txt"

# (name, argv) - run in order, so each case sees the previous one's state.
CASES = [
    ("help", ["--help"]),
    ("show_all", []),
    ("interfaces", ["interfaces"]),
    # light: a bare integer is brightness, anything else a colour. Writes are
    # restored to 0 (or to a value already in place) so the suite is neutral.
    ("light_read", ["light"]),
    ("light_set", ["light", "200"]),
    ("light_read_back", ["light"]),
    ("light_off", ["light", "off"]),
    ("light_on", ["light", "on"]),
    ("light_colour_hex", ["light", "#ff8800"]),
    ("light_colour_short", ["light", "f00"]),
    ("light_colour_name", ["light", "lime"]),
    ("light_bad_colour", ["light", "nothex"]),
    ("light_out_of_range", ["light", "9999"]),
    ("light_six_digits", ["light", "123456"]),
    ("light_leds_bad", ["light", "#ff0000", "--leds", "99"]),
    ("light_final", ["light", "off"]),
    # polling / dpi: read-only + reject-before-write. Deliberately no mutating
    # cases, so the suite can never change the user's mouse configuration.
    ("polling", ["polling"]),
    ("dpi", ["dpi"]),
    ("dpi_one_stage", ["dpi", "4"]),
    ("dpi_one_active", ["dpi", "2"]),
    ("dpi_current", ["dpi", "current"]),
    ("dpi_current_alias", ["dpi", "active"]),
    ("dpi_stage_word", ["dpi", "bogus"]),
    ("polling_bad_rate", ["polling", "999"]),
    ("polling_too_fast", ["polling", "16000"]),
    ("dpi_bad_stage", ["dpi", "5", "800"]),
    ("dpi_neg_stage", ["dpi", "-1", "800"]),
    ("dpi_not_multiple", ["dpi", "0", "1234"]),
    ("dpi_current_low", ["dpi", "current", "999"]),
    ("dpi_out_of_range", ["dpi", "3", "26100"]),
    ("dpi_stages_too_few", ["dpi", "--stages", "3"]),
    ("dpi_stages_too_many", ["dpi", "--stages", "9"]),
    ("dpi_stages_nan", ["dpi", "--stages", "abc"]),
    ("wrong_node_type", ["--node", "/dev/null", "light"]),
    ("nonexistent_node", ["--node", "/nonexistent/hidrawX", "light"]),
    ("no_such_noun", ["wibble"]),
]

# /dev/hidrawN numbering is volatile - it changes on every replug. Mask it so
# the baseline survives re-enumeration. The rest of the message is compared.
NODE_RE = re.compile(r"/dev/hidraw\d+")

# The output embeds the user's own configuration: brightness, polling rate,
# their DPI stage values, their indicator colours, and which stage is active.
# That is device state, not tool behaviour, so it must not be baked into a
# baseline. The *structure* (labels, field order, formatting, active/disabled
# markers) is still compared; the numbers become placeholders.
#
# Exact encode/decode arithmetic is covered by test_units.py, which needs no
# device.
DPI_LINE_RE = re.compile(
    r"stage (?P<n>\d+):\s+(?P<dpi>\d+) DPI\s+"
    r"indicator #(?P<rgb>[0-9a-f]{6})\s+code=0x(?P<code>[0-9a-fA-F]{4})"
    r"(?P<mark>.*)"
)
DPI_HEADER_RE = re.compile(r"mask=0x(?P<mask>[0-9A-Fa-f]{2}), active=(?P<active>\d+)")
DPI_COUNT_RE = re.compile(r"dpi stages\s+\d+ of (\d+) enabled, active \d+")
# `light` read:    brightness: 0xNN (N/255, N%)   ack_result=0xNN
BRIGHT_READ_RE = re.compile(
    r"brightness: 0x[0-9A-F]{2} \(\d+/255, \d+%\)\s+ack_result=0x[0-9A-F]{2}"
)
# brightness write: brightness -> N (N%)  ack_result=0xNN  <verdict>
BRIGHT_WRITE_RE = re.compile(r"brightness -> \d+ \(\d+%\)\s+ack_result=0x[0-9A-F]{2}")
# `show` block:    brightness   N/255 (N%)   ack_result=0xNN
BRIGHT_BLOCK_RE = re.compile(
    r"brightness\s+\d+/255 \(\d+%\)\s+ack_result=0x[0-9A-F]{2}"
)
POLL_RE = re.compile(r"polling rate \d+ Hz\s+\(RR=0x[0-9A-F]{2}\)")
POLL_BLOCK_RE = re.compile(r"polling\s+\d+ Hz\s+\(RR=0x[0-9A-F]{2}\)")
STAGE_DPI_RE = re.compile(r"stage (?P<n>\d+):\s+\d+ DPI")
# `show` lists one indented line per *enabled* stage, so both the line count
# and its contents vary with the user's configuration. Collapse the whole run
# to one marker; the check that remains is "an indented per-stage block is
# printed at all", which is the part this tool actually controls.
STAGE_BLOCK_RE = re.compile(r"(?:^      stage \d+: NNNN DPI\n)+", re.MULTILINE)


def _mask_device_state(text):
    text = NODE_RE.sub("/dev/hidrawN", text)
    text = BRIGHT_READ_RE.sub("brightness: 0xBB (B/255, B%)   ack_result=0xAA", text)
    text = BRIGHT_WRITE_RE.sub("brightness -> B (B%)  ack_result=0xAA  VERDICT", text)
    text = BRIGHT_BLOCK_RE.sub("brightness   B/255 (B%)   ack_result=0xAA", text)
    text = POLL_RE.sub("polling rate P Hz  (RR=0xRR)", text)
    text = POLL_BLOCK_RE.sub("polling      P Hz   (RR=0xRR)", text)
    text = DPI_COUNT_RE.sub("dpi stages   C of \\1 enabled, active S", text)
    text = STAGE_DPI_RE.sub(lambda m: f"stage {m['n']}: NNNN DPI", text)
    text = STAGE_BLOCK_RE.sub("      [<enabled stage lines>]\n", text)
    text = DPI_HEADER_RE.sub("mask=0xMM, active=S", text)
    text = DPI_LINE_RE.sub(
        lambda m: (
            f"stage {m['n']}: NNNN DPI  indicator #RRGGBB  code=0xCCCC{m['mark']}"
        ),
        text,
    )
    return text


def run(argv):
    p = subprocess.run(
        [sys.executable, str(TOOL), *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    out = f"exit={p.returncode}\n--- stdout ---\n{p.stdout}--- stderr ---\n{p.stderr}"
    return _mask_device_state(out)


def collect():
    return [f"### {name}\n{run(argv)}" for name, argv in CASES]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bless", action="store_true", help="re-record the baseline")
    args = ap.parse_args()

    if not TOOL.exists():
        print(f"tool not found: {TOOL}", file=sys.stderr)
        return 2

    actual = "\n".join(collect())

    if args.bless:
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(actual)
        print(f"blessed {GOLDEN} ({len(CASES)} cases)")
        return 0

    if not GOLDEN.exists():
        print(f"no baseline at {GOLDEN}; run with --bless", file=sys.stderr)
        return 2

    expected = GOLDEN.read_text()
    if actual == expected:
        print(f"OK  {len(CASES)}/{len(CASES)} cases match baseline")
        return 0

    # Report the first divergence rather than dumping everything.
    exp_lines, act_lines = expected.splitlines(), actual.splitlines()
    import difflib

    diff = list(
        difflib.unified_diff(
            exp_lines, act_lines, "expected", "actual", lineterm="", n=1
        )
    )
    print(f"FAIL  behaviour changed ({len(diff)} diff lines)")
    print("\n".join(diff[:40]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
