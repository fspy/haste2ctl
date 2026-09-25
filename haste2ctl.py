#!/usr/bin/env python3
"""
haste2ctl - control a HP / HyperX Pulsefire Haste 2 (USB 03f0:0b97):
lighting, USB polling rate and DPI stages.

Talks directly to the vendor HID interface (interface 2) via /dev/hidraw, so
there are no Python dependencies. Report layout was taken from the USB
capture and cross-checked against the live device.

Protocol (64-byte numbered output reports on the interrupt OUT endpoint):

    40 01 00 00 BB     set volatile brightness, BB = 0..255
    40 02              read brightness      -> 41 02 BB
    44 01 NN 00        begin direct lighting frame, NN chunks
    44 02 II 00 [RGB]  chunk II, up to 20 LED slots (3 bytes each)
    32 02              query polling + DPI  -> 33 02 RR MM AA [stages]
    32 01 00 00 ...    live write of that same table

    ACK: ff 01 ... report@14 subreport@15 result@16   (result 0 = success)

Brightness is volatile: it lives in the mouse's RAM and is not written to
onboard flash, so it reverts on unplug/reboot. It does persist across the
device being closed and reopened, so a single write is enough per session.

Re-applying automatically is done with a udev rule on the mouse's `add` event
(see haste2ctl.rules / haste2ctl.service), which covers both boot and replug.
A polling subcommand used to exist here; it was removed because it never
detected reconnects - it just rewrote the value on a timer - and it would
overwrite any colour frame, since a 40 01 write replaces the direct-lighting
mode. Use the udev rule instead.

Examples:
    ./haste2ctl                      report every setting
    ./haste2ctl interfaces           which hidraw node is the vendor interface
    ./haste2ctl light                read brightness
    ./haste2ctl light 128            set brightness
    ./haste2ctl light off            brightness 0
    ./haste2ctl light '#ff8800'      direct colour frame (the # keeps it
                                    distinct from a bare number)
    ./haste2ctl light lime           ...or a colour name
    ./haste2ctl polling              read the USB polling rate
    ./haste2ctl polling 1000         set it (125..8000)
    ./haste2ctl dpi                  list the DPI stage table
    ./haste2ctl dpi 3                show one stage
    ./haste2ctl dpi 3 2400           set one stage
    ./haste2ctl dpi current 2400     set whichever stage is live
    ./haste2ctl dpi --stages 5       enable the 5th slot

Polling and DPI writes are live-profile only - no save-to-flash is issued, and
the active stage stays under the mouse's own DPI button. Every write is read
back and verified before reporting success.
"""

import argparse
import os
import re
import select
import sys
import time

VID, PID = 0x03F0, 0x0B97
VENDOR_IFACE = 2  # boot mouse=0, boot keyboard=1, vendor HID=2
REPORT_LEN = 64
ACK = 0xFF

# A write is acknowledged with a 0xff ACK and nothing else - there is no data
# reply. Waiting for one burns the whole data timeout, so writes get their own
# much shorter budget. The capture shows ACKs arriving in ~300 us.
ACK_TIMEOUT = 0.25

# Boot mouse / boot keyboard report descriptors, used to positively identify
# the vendor interface without trusting interface ordering.
BOOT_RDESC_SIZES = {94, 93}

# --------------------------------------------------------------------------
# Polling / DPI config report (32 02 query, 32 01 live write)
# --------------------------------------------------------------------------
#   32 02                             query
#   33 02 RR MM AA [stage records]    reply
#   32 01 00 00 RR MM AA [stages]     live write
#
# RR is a divisor: Hz = 8000 / RR. The endpoint's bInterval=1 at High Speed
# caps this at 8000 Hz, which is why 0x01 is the fastest legal value.
POLL_RATES = {
    125: 0x40,
    250: 0x20,
    500: 0x10,
    1000: 0x08,
    2000: 0x04,
    4000: 0x02,
    8000: 0x01,
}
POLL_BASE_HZ = 8000

# Layout inside the reply (and, offset by 4, the live write).
RR_OFFSET = 2  # poll divisor
STAGE_MASK_OFFSET = 3  # which stages are enabled
ACTIVE_STAGE_OFFSET = 4
STAGE_OFFSET = 5  # first stage record
STAGE_RECORD_LEN = 5  # u16 dpi code (LE) + R, G, B
MAX_STAGES = 5

# A stage's DPI is stored as DPI/50 - 1, so only multiples of 50 round-trip.
DPI_STEP = 50
DPI_MIN = 50
DPI_MAX = 26000  # native sensor maximum for this mouse


def poll_rate_to_divisor(hz):
    """Hz -> RR, rejecting anything this mouse cannot do."""
    try:
        return POLL_RATES[int(hz)]
    except (KeyError, ValueError, TypeError):
        raise DevError(
            f"unsupported polling rate {hz!r}; choose from {sorted(POLL_RATES)}"
        ) from None


def divisor_to_poll_rate(divisor):
    """RR -> Hz. Returns 0 for the zero divisor, which is not a real rate."""
    return POLL_BASE_HZ // divisor if divisor else 0


def encode_dpi(dpi):
    """DPI -> the device's u16 stage code, rejecting values that cannot round-trip."""
    dpi = int(dpi)
    if not DPI_MIN <= dpi <= DPI_MAX:
        raise DevError(f"DPI must be {DPI_MIN}-{DPI_MAX}, got {dpi}")
    if dpi % DPI_STEP:
        raise DevError(
            f"DPI {dpi} is not a multiple of {DPI_STEP}, so the mouse could "
            f"not read it back identically; use {dpi - dpi % DPI_STEP} "
            f"or {dpi - dpi % DPI_STEP + DPI_STEP}"
        )
    return dpi // DPI_STEP - 1


def decode_dpi(code):
    """The device's u16 stage code -> DPI."""
    return (code + 1) * DPI_STEP


def stage_offset(stage):
    if not 0 <= stage < MAX_STAGES:
        raise DevError(f"stage must be 0-{MAX_STAGES - 1}, got {stage}")
    return STAGE_OFFSET + stage * STAGE_RECORD_LEN


def read_stage_code(reply, stage):
    off = stage_offset(stage)
    return reply[off] | (reply[off + 1] << 8)


def write_stage_code(reply, stage, code):
    off = stage_offset(stage)
    reply[off] = code & 0xFF
    reply[off + 1] = (code >> 8) & 0xFF


def stage_colour(reply, stage):
    off = stage_offset(stage) + 2
    return reply[off], reply[off + 1], reply[off + 2]


# The mouse has 5 stage slots. Firmware accepted mask=0x1F (all five) but
# rejected anything with bits above bit 4 set, so 4 or 5 is the real range.
MIN_ENABLED_STAGES = 4
CURRENT_STAGE_ALIASES = ("current", "active")


def resolve_stage(text, reply):
    """'current'/'active' -> the active stage index; anything else must be 0-4.

    Returns None when no stage was named at all.
    """
    if text is None:
        return None
    if text.lower() in CURRENT_STAGE_ALIASES:
        stage = reply[ACTIVE_STAGE_OFFSET]
        if not (reply[STAGE_MASK_OFFSET] >> stage) & 1:
            raise DevError(f"active stage {stage} is disabled in the mask")
        return stage
    try:
        return int(text)
    except ValueError:
        raise DevError(
            f"stage must be 0-{MAX_STAGES - 1} or "
            f"{'/'.join(CURRENT_STAGE_ALIASES)}, got {text!r}"
        ) from None


def mask_for_stage_count(count):
    """N enabled stages -> the mask the mouse expects."""
    count = int(count)
    if not MIN_ENABLED_STAGES <= count <= MAX_STAGES:
        raise DevError(
            f"stage count must be {MIN_ENABLED_STAGES}-{MAX_STAGES} "
            f"(the mouse has {MAX_STAGES} slots), got {count}"
        )
    return (1 << count) - 1


class DevError(Exception):
    pass


# --------------------------------------------------------------------------
# device discovery
# --------------------------------------------------------------------------


def _hid_id(uevent_path):
    try:
        with open(uevent_path) as fh:
            for line in fh:
                if line.startswith("HID_ID="):
                    parts = line.strip().split("=")[1].split(":")
                    return int(parts[1], 16), int(parts[2], 16)
    except OSError:
        pass
    return None


def _rdesc_size(dev_path):
    """Real byte length of the report descriptor.

    NB: os.path.getsize() is useless here - sysfs reports the page size (4096)
    for every attribute, so the file has to actually be read.
    """
    try:
        with open(os.path.join(dev_path, "report_descriptor"), "rb") as fh:
            return len(fh.read())
    except OSError:
        return -1


def _iface_number(real_path):
    m = re.search(r":1\.(\d+)(?:\D|$)", real_path)
    return int(m.group(1)) if m else None


def enumerate_interfaces():
    """Return [{node, iface, rdesc, name}] for every hidraw node of our mouse."""
    found = []
    base = "/sys/class/hidraw"
    try:
        nodes = sorted(os.listdir(base), key=lambda n: int(n.replace("hidraw", "")))
    except OSError:
        return found
    for node in nodes:
        devdir = os.path.join(base, node, "device")
        hid = _hid_id(os.path.join(devdir, "uevent"))
        if hid != (VID, PID):
            continue
        real = os.path.realpath(devdir)
        found.append({
            "node": os.path.join("/dev", node),
            "iface": _iface_number(real),
            "rdesc": _rdesc_size(devdir),
            "name": "HP, Inc HyperX Pulsefire Haste 2",
        })
    return found


def _by_interface_number(ifaces):
    """Strategy 1: trust the known vendor interface number."""
    matches = [i for i in ifaces if i["iface"] == VENDOR_IFACE]
    if not matches:
        return None
    return matches[0]["node"], f"USB interface {VENDOR_IFACE} (vendor HID)"


def _sole_non_boot_interface(ifaces):
    """Strategy 2: take the one interface that is not a boot mouse/keyboard."""
    others = [i for i in ifaces if i["rdesc"] not in BOOT_RDESC_SIZES]
    if len(others) != 1:
        return None
    only = others[0]
    return only["node"], f"only non-boot interface (report desc {only['rdesc']}B)"


# Ordered by confidence: explicit interface number first, then inference.
VENDOR_STRATEGIES = (_by_interface_number, _sole_non_boot_interface)


def select_vendor(ifaces):
    """Pick the vendor HID interface from `ifaces`.

    Returns (node, rationale), or None if no strategy matches. Pure
    selection - no waiting, no I/O - so it can be retried unchanged.
    """
    for strategy in VENDOR_STRATEGIES:
        found = strategy(ifaces)
        if found:
            return found
    return None


def _no_device_error():
    return DevError(
        f"no hidraw node found for {VID:04x}:{PID:04x}\n"
        f"  is the mouse plugged in? try: lsusb -d {VID:04x}:{PID:04x}"
    )


def _ambiguous_error(ifaces):
    return DevError(
        "ambiguous hidraw nodes: "
        + ", ".join(
            f"{i['node']}(iface={i['iface']},rdesc={i['rdesc']}B)" for i in ifaces
        )
    )


def _poll_for_vendor(deadline):
    """Retry enumeration until the vendor interface appears or time runs out.

    Returns (found, ifaces) where found is (node, rationale) or None, and
    ifaces is the last enumeration seen - needed to explain a failure.
    """
    while True:
        ifaces = enumerate_interfaces()
        found = select_vendor(ifaces)
        if found:
            return found, ifaces
        if time.time() >= deadline:
            return None, ifaces
        time.sleep(0.25)


def find_vendor_node(override=None, wait=0.0):
    """Locate /dev/hidrawN for the vendor interface, with an explicit rationale.

    `wait` (seconds) makes this tolerate being called before the device has
    finished enumerating - udev fires per-interface as they appear, so the
    boot mouse interface can be there before the vendor one is.
    """
    if override:
        return override, "forced by --node"

    found, ifaces = _poll_for_vendor(time.time() + max(0.0, wait))
    if found:
        return found
    if not ifaces:
        raise _no_device_error()
    raise _ambiguous_error(ifaces)


# --------------------------------------------------------------------------
# device I/O
# --------------------------------------------------------------------------


class Mouse:
    def __init__(self, node):
        self.node = node
        # Set by set_color; consumed by the brightness write path, because a
        # colour frame outranks a later brightness write until it settles.
        self.colour_frame_pending = False
        try:
            self.fd = os.open(node, os.O_RDWR)
        except PermissionError:
            raise DevError(
                f"permission denied opening {node}\n"
                f"  either run as root, or install the udev rule:"
            ) from None
        except OSError as e:
            raise DevError(f"cannot open {node}: {e}") from None

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def drain(self):
        """Discard reports queued from previous transactions.

        Must not block. A `select` with a real timeout here would tax every
        single write by that timeout, because the common case is an empty
        queue - so the first probe is non-blocking.
        """
        while select.select([self.fd], [], [], 0)[0]:
            if not os.read(self.fd, REPORT_LEN):
                return

    def _send(self, body):
        pkt = (bytes(body) + b"\x00" * REPORT_LEN)[:REPORT_LEN]
        self.drain()
        n = os.write(self.fd, pkt)
        if n != REPORT_LEN:
            raise DevError(f"short write to {self.node}: {n}/{REPORT_LEN} bytes")

    def _read_report(self, timeout):
        """Wait up to `timeout` for one report, or None if none arrives."""
        ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not ready:
            return None
        data = os.read(self.fd, REPORT_LEN)
        if not data:
            raise DevError("device disconnected")
        return data

    @staticmethod
    def _is_ack(data, report_id, subreport):
        """Is this ACK the answer to the command we just sent?"""
        return data[14] == report_id and data[15] == subreport

    def _await_ack(self, timeout, report_id, subreport):
        """Read until the ACK for one command lands. Returns its result byte.

        A write is answered by an ACK and nothing else, so this returns as soon
        as that ACK arrives rather than waiting out a timeout. The result byte
        is 0x00 on success; None means no ACK arrived.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self._read_report(deadline - time.time())
            if data is None:
                return None
            if data[0] == ACK and self._is_ack(data, report_id, subreport):
                return data[16]
        return None

    def _collect(self, timeout, want):
        """Read reports until one starts with `want`, or timeout."""
        deadline = time.time() + timeout
        acks = []
        while time.time() < deadline:
            data = self._read_report(deadline - time.time())
            if data is None:
                return None, acks
            if data[0] == want:
                return data, acks
            if data[0] == ACK:
                acks.append(data)
        return None, acks

    @staticmethod
    def _check(acks, report_id, subreport):
        """Verify the ACK for `report_id`/`subreport` succeeded (result byte == 0)."""
        for a in acks:
            if a[14] == report_id and a[15] == subreport:
                return a[16]
        return None

    def read_brightness(self, timeout=1.0):
        self._send([0x40, 0x02])
        data, acks = self._collect(timeout, want=0x41)
        result = self._check(acks, 0x40, 0x02)
        if data is None:
            raise DevError(
                "no 41 02 reply - wrong interface, or the mouse is asleep\n"
                "  (click it to wake, then retry)"
            )
        return data[2], result

    def set_brightness(self, level, timeout=ACK_TIMEOUT):
        level = max(0, min(255, int(level)))
        self._send([0x40, 0x01, 0x00, 0x00, level])
        return self._await_ack(timeout, 0x40, 0x01)

    def read_config(self, timeout=1.0):
        """Query polling rate + DPI stage table. Returns (reply, ack_result).

        The reply is the full 64-byte 33 02 report; treat it as read-only and
        hand a modified *copy* to write_config so nothing else gets clobbered.
        """
        self._send([0x32, 0x02])
        data, acks = self._collect(timeout, want=0x33)
        result = self._check(acks, 0x32, 0x02)
        if data is None:
            raise DevError(
                "no 33 02 reply - wrong interface, or the mouse is asleep\n"
                "  (click it to wake, then retry)"
            )
        return data, result

    def write_config(self, reply, timeout=ACK_TIMEOUT):
        """Write back a modified copy of a read_config reply.

        Only the first two bytes change (33 02 -> 32 01 00 00); everything
        after the header is the mouse's own current table, sent back verbatim
        so untouched fields survive. No save-to-flash is issued - this is the
        live/AP profile only.
        """
        self._send(bytes([0x32, 0x01, 0x00, 0x00]) + bytes(reply[2:62]))
        return self._await_ack(timeout, 0x32, 0x01)

    def set_color(self, rgb, leds=1, timeout=ACK_TIMEOUT):
        """Direct lighting frame: 1 chunk holding `leds` RGB triples."""
        if leds < 1 or leds > 20:
            raise DevError("leds must be 1..20 (protocol caps a chunk at 20 slots)")
        begin = [0x44, 0x01, 0x01, 0x00]  # begin frame, 1 chunk
        chunk = [0x44, 0x02, 0x00, 0x00] + list(rgb) * leds
        results = []
        for pkt in (begin, chunk):
            self._send(pkt)
            results.append(self._await_ack(timeout, 0x44, pkt[1]))
        self.colour_frame_pending = True
        return results


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

_HEX_DIGITS = frozenset("0123456789abcdef")

# Same 8 names the CLI has always accepted - do not widen without saying so.
NAMED_COLORS = {
    "black": (0, 0, 0),
    "red": (255, 0, 0),
    "green": (0, 255, 0),
    "blue": (0, 0, 255),
    "white": (255, 255, 255),
    "lime": (0, 255, 0),
    "off": (0, 0, 0),
    "on": (255, 255, 255),
}


def _is_hex(text):
    return all(c in _HEX_DIGITS for c in text.lower())


def _expand_short_hex(text):
    """`f00` -> `ff0000`; anything else is passed through unchanged."""
    if len(text) == 3 and _is_hex(text):
        return "".join(c * 2 for c in text.lower())
    return text


def parse_rgb(text):
    """Accept a colour name, RRGGBB, or the short #RGB form."""
    s = _expand_short_hex(text.strip().lstrip("#"))
    if s.lower() in NAMED_COLORS:
        return NAMED_COLORS[s.lower()]
    if len(s) != 6 or not _is_hex(s):
        raise argparse.ArgumentTypeError("expected RRGGBB hex or a colour name")
    return tuple(int(s[i : i + 2], 16) for i in (0, 2, 4))


def _interface_tag(iface, chosen):
    """Label for one row: which interface is it, and is it the one we picked."""
    if iface["node"] == chosen:
        return "   <== vendor interface"
    if iface["rdesc"] in BOOT_RDESC_SIZES:
        return "   (boot)"
    return ""


def _interface_row(iface, chosen):
    access = "rw" if os.access(iface["node"], os.R_OK | os.W_OK) else "no-access"
    return (
        f"  {iface['node']:16s} iface={iface['iface']}  "
        f"report_desc={iface['rdesc']:4d}B  {access}"
        f"{_interface_tag(iface, chosen)}"
    )


def _format_stage(reply, stage):
    """One stage as a line, noting whether it is active or disabled."""
    code = read_stage_code(reply, stage)
    r, g, b = stage_colour(reply, stage)
    if stage == reply[ACTIVE_STAGE_OFFSET]:
        note = "  <- active"
    elif not (reply[STAGE_MASK_OFFSET] >> stage) & 1:
        note = "  (disabled)"
    else:
        note = ""
    return (
        f"    stage {stage}: {decode_dpi(code):>5d} DPI  "
        f"indicator #{r:02x}{g:02x}{b:02x}  code=0x{code:04X}{note}"
    )


def _format_stages(reply):
    return "\n".join(_format_stage(reply, s) for s in range(MAX_STAGES))


def cmd_polling(args):
    node, why = find_vendor_node(args.node, args.wait)
    with Mouse(node) as m:
        reply, _ = m.read_config()
        current = divisor_to_poll_rate(reply[RR_OFFSET])
        if args.hz is None:
            print(f"{node}: polling rate {current} Hz  (RR=0x{reply[RR_OFFSET]:02X})")
            return 0

        divisor = poll_rate_to_divisor(args.hz)
        if divisor == reply[RR_OFFSET]:
            print(f"{node}: already {current} Hz, nothing written")
            return 0

        modified = bytearray(reply)
        modified[RR_OFFSET] = divisor
        ack = m.write_config(modified)
        check, _ = m.read_config()
        got = divisor_to_poll_rate(check[RR_OFFSET])
        ok = check[RR_OFFSET] == divisor
        print(
            f"{node}: polling {current} -> {got} Hz  "
            f"ack=0x{ack:02X}  {'ok' if ok else 'NOT APPLIED (device refused)'}"
        )
        return 0 if ok else 1


def _enabled_stage_count(reply):
    return bin(reply[STAGE_MASK_OFFSET]).count("1")


def _print_dpi(node, reply, stage=None):
    """Print the whole stage table, or just one stage when `stage` is given."""
    print(
        f"{node}: DPI stages  (mask=0x{reply[STAGE_MASK_OFFSET]:02X}, "
        f"active={reply[ACTIVE_STAGE_OFFSET]})"
    )
    if stage is None:
        print(_format_stages(reply))
    else:
        print(_format_stage(reply, stage))


def _apply_dpi(node, mouse, reply, stage, code):
    """Write a modified table, re-read, and report whether the value stuck."""
    if read_stage_code(reply, stage) == code:
        print(f"{node}: stage {stage} already {decode_dpi(code)} DPI, nothing written")
        return True
    modified = bytearray(reply)
    write_stage_code(modified, stage, code)
    ack = mouse.write_config(modified)
    check, _ = mouse.read_config()
    got = decode_dpi(read_stage_code(check, stage))
    ok = got == decode_dpi(code)
    print(
        f"{node}: stage {stage} -> {got} DPI  "
        f"ack=0x{ack:02X}  {'ok' if ok else 'NOT APPLIED (device refused)'}"
    )
    if ok and not (check[STAGE_MASK_OFFSET] >> stage) & 1:
        print(
            f"  note: stage {stage} is disabled in the mask, so the "
            f"DPI button will not step to it"
        )
    return ok


def _set_stage_count(node, mouse, reply, count):
    """Enable the first `count` stages. Slots beyond the mask keep their values."""
    mask = mask_for_stage_count(count)
    was = _enabled_stage_count(reply)
    if reply[STAGE_MASK_OFFSET] == mask:
        print(f"{node}: already {was} stages enabled, nothing written")
        return True
    modified = bytearray(reply)
    modified[STAGE_MASK_OFFSET] = mask
    ack = mouse.write_config(modified)
    check, _ = mouse.read_config()
    now = _enabled_stage_count(check)
    ok = check[STAGE_MASK_OFFSET] == mask
    print(
        f"{node}: stages {was} -> {now} enabled (mask=0x{mask:02X})  "
        f"ack=0x{ack:02X}  {'ok' if ok else 'NOT APPLIED (device refused)'}"
    )
    if ok and now < was:
        print(
            f"  note: {was - now} slot(s) just disabled - the DPI button will "
            f"not step to them, though their values are kept"
        )
    return ok


def _set_or_show_stage(node, mouse, reply, args):
    stage = resolve_stage(args.stage, reply)
    if stage is None:
        _print_dpi(node, reply)
        return 0
    stage_offset(stage)
    if args.dpi is None:
        # `dpi 4` inspects one stage rather than writing it.
        _print_dpi(node, reply, stage)
        return 0
    return 0 if _apply_dpi(node, mouse, reply, stage, encode_dpi(args.dpi)) else 1


def cmd_dpi(args):
    node, why = find_vendor_node(args.node, args.wait)
    with Mouse(node) as m:
        reply, _ = m.read_config()
        if args.stages is not None:
            return 0 if _set_stage_count(node, m, reply, args.stages) else 1
        return _set_or_show_stage(node, m, reply, args)


def cmd_interfaces(_args):
    # `_args` because argparse dispatches as fn(args) uniformly; this one
    # genuinely ignores the parsed arguments.
    ifaces = enumerate_interfaces()
    if not ifaces:
        print(f"device {VID:04x}:{PID:04x} not found", file=sys.stderr)
        return 1
    try:
        chosen, why = find_vendor_node()
    except DevError as e:
        chosen, why = None, str(e)
    print(f"USB {VID:04x}:{PID:04x}  HP, Inc HyperX Pulsefire Haste 2\n")
    for i in ifaces:
        print(_interface_row(i, chosen))
    if chosen:
        print(f"\nselected: {chosen}  ({why})")
    else:
        print(f"\ncould not auto-select: {why}")
    return 0


def _format_acks(results):
    """Render ACK results as a list, exactly as the CLI has always shown them."""
    return [None if r is None else f"0x{r:02X}" for r in results]


def _all_acks_succeeded(results):
    return all(r == 0 for r in results)


# `light <value>` must tell a brightness from a colour. A bare integer is
# always a brightness; a colour must be written with a '#' or as a name. That
# is unambiguous by construction - the alternative (guessing that 123456 meant
# #123456 but 300 meant a brightness) silently turns typos into colours.
BRIGHTNESS_MAX = 255
LIGHT_SHORTCUTS = {"off": 0, "on": 255}

# A direct colour frame is sticky. Roughly COLOUR_SETTLE_S after one lands the
# firmware reasserts it at full brightness, which undoes any 40 01 brightness
# write issued in the meantime - the write is ACKed and does take effect, it
# just does not stay. Measured on this mouse at ~2 s.
#
# So a brightness write that follows a colour frame in the same process is
# re-applied once, after the settle window. The common case (brightness only,
# e.g. the udev unit on plug-in) never pays this cost.
COLOUR_SETTLE_S = 2.2
BRIGHTNESS_ATTEMPTS = 2


def _is_plain_int(text):
    body = text[1:] if text[:1] in "+-" else text
    return bool(body) and body.isdigit()


def _hex_hint(text):
    """Offer a '#'-prefixed colour alternative, but only if it would read as one."""
    digits = text.lstrip("+-")
    if len(digits) in (3, 6) and all(c in _HEX_DIGITS for c in digits.lower()):
        return f" If you meant the colour #{digits}, write it as '#{digits}'."
    return ""


def parse_light_target(text):
    """Classify a `light` argument as ('level', int) or ('color', (r,g,b))."""
    key = text.strip()
    if key.lower() in LIGHT_SHORTCUTS:
        return "level", LIGHT_SHORTCUTS[key.lower()]
    if _is_plain_int(key):
        level = int(key, 10)
        if not 0 <= level <= BRIGHTNESS_MAX:
            raise DevError(
                f"{key} is out of range for brightness "
                f"(0-{BRIGHTNESS_MAX})." + _hex_hint(key)
            )
        return "level", level
    try:
        return "color", parse_rgb(key)
    except argparse.ArgumentTypeError as e:
        raise DevError(str(e)) from None


def _report_brightness(node, level, ack, verdict):
    print(
        f"{node}: brightness -> {level} ({round(level * 100 / 255)}%)  "
        f"ack_result=0x{ack:02X}  {verdict}"
    )


def _write_brightness(mouse, level):
    res = mouse.set_brightness(level)
    got, _ = mouse.read_brightness()
    return got, res


def _needs_settle(mouse, got, level, sticky):
    """Should this write wait out the colour-frame window and re-apply?"""
    return got == level and (sticky or mouse.colour_frame_pending)


def _set_brightness_verified(mouse, level, sticky=False):
    """Write brightness and confirm it stuck. Returns (readback, ack).

    Retries once on a plain mismatch, and re-applies after the colour-frame
    settle window when it knows a frame is in play - either because one was
    sent in this process, or because `sticky` was asked for explicitly (which
    is what you need across separate invocations, e.g. from a script).
    """
    got, res = _write_brightness(mouse, level)
    for _ in range(BRIGHTNESS_ATTEMPTS - 1):
        if got == level:
            break
        got, res = _write_brightness(mouse, level)
    if _needs_settle(mouse, got, level, sticky):
        time.sleep(COLOUR_SETTLE_S)
        got, res = _write_brightness(mouse, level)
        mouse.colour_frame_pending = False
    return got, res


def _show_brightness(node, why, mouse):
    level, res = mouse.read_brightness()
    print(f"{node} ({why})")
    print(
        f"brightness: 0x{level:02X} ({level}/{BRIGHTNESS_MAX}, "
        f"{round(level * 100 / BRIGHTNESS_MAX)}%)   ack_result=0x{res:02X}"
    )


def _write_colour(node, mouse, value, leds):
    results = mouse.set_color(value, leds)
    ok = _all_acks_succeeded(results)
    verdict = "ok" if ok else "ACK error"
    print(
        f"{node}: color #{value[0]:02x}{value[1]:02x}{value[2]:02x} "
        f"x{leds} slot(s)  acks={_format_acks(results)}  {verdict}"
    )
    return 0 if ok else 1


def cmd_light(args):
    node, why = find_vendor_node(args.node, args.wait)
    with Mouse(node) as m:
        if args.value is None:
            _show_brightness(node, why, m)
            return 0

        kind, value = parse_light_target(args.value)
        if kind == "color":
            return _write_colour(node, m, value, args.leds)

        got, res = _set_brightness_verified(m, value, args.sticky)
    ok = got == value
    _report_brightness(
        node, got, res, "ok" if ok else f"MISMATCH (want {value})"
    )
    return 0 if ok else 1


def cmd_show(args):
    """No noun given: report every setting this tool can read."""
    node, _ = find_vendor_node(args.node, args.wait)
    with Mouse(node) as m:
        level, res = m.read_brightness()
        reply, _ = m.read_config()
    print(f"USB {VID:04x}:{PID:04x}  HP, Inc HyperX Pulsefire Haste 2   {node}")
    print(
        f"  brightness   {level}/{BRIGHTNESS_MAX} "
        f"({round(level * 100 / BRIGHTNESS_MAX)}%)   ack_result=0x{res:02X}"
    )
    print(
        f"  polling      {divisor_to_poll_rate(reply[RR_OFFSET])} Hz"
        f"   (RR=0x{reply[RR_OFFSET]:02X})"
    )
    print(
        f"  dpi stages   {_enabled_stage_count(reply)} of {MAX_STAGES} enabled,"
        f" active {reply[ACTIVE_STAGE_OFFSET]}"
    )
    for stage in range(MAX_STAGES):
        if (reply[STAGE_MASK_OFFSET] >> stage) & 1:
            dpi = decode_dpi(read_stage_code(reply, stage))
            print(f"      stage {stage}: {dpi:>5d} DPI")
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="haste2ctl",
        description="Control a HyperX Pulsefire Haste 2 (03f0:0b97): "
        "lighting, USB polling rate and DPI stages.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="With no noun, every setting is reported. Brightness is "
        "volatile - it is not saved to onboard flash.",
    )
    ap.add_argument("--node", help="explicit /dev/hidrawN (skips auto-detection)")
    ap.add_argument(
        "--wait",
        type=float,
        default=0.0,
        metavar="SEC",
        help="wait up to SEC seconds for the vendor interface to "
        "appear (for udev/systemd use, where enumeration races)",
    )
    sub = ap.add_subparsers(dest="noun", metavar="<noun>")

    sub.add_parser("interfaces", help="show this mouse's hidraw nodes").set_defaults(
        fn=cmd_interfaces
    )

    p = sub.add_parser("light", help="brightness or colour")
    p.add_argument(
        "value",
        nargs="?",
        metavar="VALUE",
        help=f"0-{BRIGHTNESS_MAX} for brightness, on/off, or a "
        f"colour as #RRGGBB (the # keeps it distinct from a "
        f"number) or a colour name",
    )
    p.add_argument("--leds", type=int, default=1, help="LED slot count (default 1)")
    p.add_argument(
        "--sticky",
        action="store_true",
        help=f"wait out the {COLOUR_SETTLE_S}s colour-frame settle window and "
             f"re-apply, so the value survives a colour frame sent by an "
             f"earlier invocation (costs that much time)")
    p.set_defaults(fn=cmd_light)

    p = sub.add_parser("polling", help="USB polling rate")
    p.add_argument(
        "hz",
        nargs="?",
        type=int,
        metavar="HZ",
        help=f"target rate; one of {sorted(POLL_RATES)}",
    )
    p.set_defaults(fn=cmd_polling)

    p = sub.add_parser("dpi", help="DPI stages")
    p.add_argument(
        "stage",
        nargs="?",
        metavar="STAGE",
        help=f"stage index 0-{MAX_STAGES - 1}, or "
        f"{'/'.join(CURRENT_STAGE_ALIASES)} for the active one",
    )
    p.add_argument(
        "dpi",
        nargs="?",
        type=int,
        metavar="DPI",
        help=f"new DPI, multiple of {DPI_STEP}, {DPI_MIN}-{DPI_MAX}",
    )
    p.add_argument(
        "--stages",
        type=int,
        metavar="N",
        help=f"enable the first N stages ({MIN_ENABLED_STAGES}-{MAX_STAGES}) instead",
    )
    p.set_defaults(fn=cmd_dpi)

    ap.set_defaults(fn=cmd_show)
    args = ap.parse_args()
    try:
        return args.fn(args)
    except DevError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
