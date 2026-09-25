# HyperX Pulsefire Haste 2 — protocol notes and `haste2ctl`

Reverse-engineered from two USBPcap2 captures taken on Windows 11 with NGENUITY
running, then verified directly against the live device on Linux.

`haste2ctl` controls **lighting, USB polling rate and DPI stages** on this
mouse (USB `03f0:0b97`, an HP-branded HyperX part). It is a dependency-free
Python script that talks to `/dev/hidraw` directly.

| File | What it is |
|---|---|
| `haste2ctl.py` | the tool |
| `test_units.py` | pure-helper tests, no device needed |
| `test_cli.py` | golden-output CLI test against the live mouse |
| `tests/golden.txt` | recorded baseline for `test_cli.py` |
| `haste2ctl.rules` | udev rule: apply lighting on plug-in |
| `haste2ctl.service` | systemd oneshot the rule triggers |
| `tools/pcap_summary.py` | dependency-free pcapng + USBPcap2 reader |
| `tools/pcap_diff.py` | reproduces the "both captures are identical" result |
| `turned_lights_{on,off}.pcapng` | the original captures |
| `lsusb.txt` | `lsusb -v` dump of the device on Linux |

## Device

| | |
|---|---|
| Marketing name | HP, Inc HyperX Pulsefire Haste 2 |
| VID:PID | `03f0:0b97` |
| bcdDevice | `0x1111` |
| Bus speed | High Speed (480 Mbps) |
| Interfaces | 0 = boot mouse (EP 0x81 IN)<br>1 = boot keyboard (EP 0x82 IN)<br>**2 = vendor HID (EP 0x83 IN, EP 0x04 OUT)** |

All configuration is done through **interface 2**, a 64-byte numbered-report
vendor HID interface (598-byte report descriptor). The boot interfaces are
untouched.

`0x03f0` is **HP, Inc** — this is *not* a SteelSeries device and *not* a
Sensei 310. SteelSeries mice use VID `0x1038`. Neither `rivalcfg` nor
`ngenuity` will touch this hardware; they gate on exact VID/PID and this PID is
in neither tool's device list.

On Linux the vendor interface shows up as a separate `hidraw` node, e.g.
`/dev/hidraw3` (the number is volatile and changes on every replug). The 598-byte report descriptor is a reliable way to tell it
apart from the 94-byte (mouse) and 93-byte (keyboard) boot nodes.

## Protocol

64-byte output reports on the interrupt OUT endpoint, zero-padded. Byte 0 is the
report ID.

| Report | Meaning |
|---|---|
| `40 01 00 00 BB` | set **volatile** brightness, `BB` = 0..255 |
| `40 02` | read brightness → reply `41 02 BB` |
| `44 01 NN 00` | begin direct lighting frame, `NN` chunks |
| `44 02 II 00 [RGB triples]` | chunk `II`, up to 20 LED slots (3 bytes each) |
| `10 01` | device info query → reply `11 01` |
| `32 02` | query polling + DPI table → reply `33 02 RR MM AA [stages]` |
| `32 01 00 00 RR MM AA [stages]` | live write of that same table |

ACK format (first byte `0xff`):

```
ff 01 e1 00 11 00 95 59 65 04 69 11 00 00 | report | sub | result | ...
 0  1  2  3  4  5  6  7  8  9  10 11 12 13    14     15     16
```

* `result` (byte 16) `0x00` = success
* unsolicited `45 02 00 …` = device notification, ignore

Brightness is **volatile** — it is not written to the mouse's onboard flash, so
it must be re-applied after reconnect. The mouse has 1 LED slot (logo), so
"lights off" is brightness `0x00` or an all-black direct frame.

## The two captures

`turned_lights_on.pcapng` and `turned_lights_off.pcapng` turned out to be
**byte-identical** in payload content, so neither contains the packet that
changed the lighting:

```
ON : 936 non-empty interrupt transfers
OFF: 1045 non-empty interrupt transfers
=> IDENTICAL for the entire common prefix
ON : 375 OUT, 2 unique -> ['440101000000', '440200000000']
OFF: 418 OUT, 2 unique -> ['440101000000', '440200000000']
```

Both files contain only a repeating ~25 ms cycle of

```
OUT 44 01 01 00 …   begin direct lighting frame, 1 chunk
OUT 44 02 00 00 …   chunk 0, zero RGB triples  -> all-black frame = lights OFF
IN  ff 01 … 44 01/02 … 00 00        success ACK
IN  45 02 00 …                     notification
```

i.e. both captures are "lights off". There is no `40 01` brightness write and
no non-black chunk in either file, so the write that turned the lights on was
not captured — it either landed outside the capture window or went to onboard
flash and only took effect on replug. There were zero HID `SET_REPORT` control
transfers in either file; the only 6 control transfers are enumeration.

That result is reproducible — it is not a claim you have to take on trust:

```bash
tools/pcap_diff.py turned_lights_on.pcapng turned_lights_off.pcapng
```

`tools/pcap_summary.py` is a dependency-free pcapng + USBPcap2 reader (no
scapy) if you want to inspect a capture yourself. The parser reports how many
bytes it could not account for, which is how the 27-vs-28-byte header question
in the two files was settled.

## Tool

`haste2ctl.py` — dependency-free, talks to `/dev/hidraw` directly.

Settings are grouped by noun; a bare noun reads, a trailing value writes.
With no noun at all, everything is reported.

```bash
./haste2ctl.py                    # report every setting
./haste2ctl.py interfaces         # hidraw nodes, and which one is the vendor interface

./haste2ctl.py light              # read brightness./haste2ctl.py light 128          # set brightness (0-255)
./haste2ctl.py light off          # brightness 0
./haste2ctl.py light '#ff8800'    # direct colour frame - the '#' keeps it
                                  # distinct from a bare number
./haste2ctl.py light lime         # ...or a colour name

./haste2ctl.py polling            # read the USB polling rate
./haste2ctl.py polling 1000       # set it (125..8000)

./haste2ctl.py dpi                # the whole stage table
./haste2ctl.py dpi 3              # one stage
./haste2ctl.py dpi 3 2400         # set stage 3 (multiples of 50)
./haste2ctl.py dpi current 2400   # set whichever stage is live
./haste2ctl.py dpi --stages 5     # enable the 5th slot
```

A bare number to `light` is always brightness and nothing else, so a typo
cannot silently become a colour:

```
$ ./haste2ctl.py light 300
error: 300 is out of range for brightness (0-255). If you meant the colour
#300, write it as '#300'.
```
```

## Polling rate and DPI

Read out of the mouse with `32 02`; written back with `32 01 00 00 …`. Both
operations are **read-modify-write**: the tool queries the current 64-byte
table, changes only the field you asked for, and sends the rest back verbatim
so stage colours and the reserved records survive. Every write is then
re-queried and compared before success is reported.

`RR` is a divisor — `Hz = 8000 / RR`:

| RR | Rate |
|---|---|
| `0x40` / `0x20` / `0x10` / `0x08` | 125 / 250 / 500 / 1000 Hz |
| `0x04` / `0x02` / `0x01` | 2000 / 4000 / **8000 Hz** |

8000 Hz is also the hardware ceiling here: all four interrupt endpoints have
`bInterval=1` at High Speed, which is one microframe (125 µs). The firmware
setting and the endpoint limit agree.

A stage's DPI is stored as `DPI/50 - 1`, so only multiples of 50 round-trip —
the tool refuses anything else rather than let the mouse read back a different
value than you asked for.

Stock configuration on this unit: 4 stages enabled (`MM=0x0F`), 400/800/1600/
3200 DPI with red/blue/yellow/green indicators, plus a disabled 5th record.
Writes are live-profile only — no save-to-flash is issued, and the active
stage remains under the mouse's own DPI button.

Every write is verified against the device's own `result` byte and read back
with `40 02` where applicable.

### udev

Already present on this machine as `/etc/udev/rules.d/00-pulsefire.rules`:

```
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="03f0", ATTRS{idProduct}=="0b97", MODE="0666"
```

Without it, run as root or `MODE="0660", GROUP="input"`.

## Automatic application (recommended)

Brightness lives in the mouse's RAM, so it reverts on unplug/reboot. Two ways
to re-apply it:

**udev + systemd (recommended).** Fires on every `add`, so it covers boot *and*
replugging mid-session, with no daemon and no polling.

```bash
sudo install -m 0644 haste2ctl.rules /etc/udev/rules.d/99-haste2ctl.rules
sudo install -m 0644 haste2ctl.service /etc/systemd/system/haste2ctl.service
sudo udevadm control --reload-rules
sudo systemctl daemon-reload
```

To change the level, edit the value in the unit's `ExecStart` — `0` for off,
`255` for full, or any 0–255. To pin a colour, or to set polling or DPI on
plug-in instead, swap the noun:

```
ExecStart=/home/fspy/ngenuity2/haste2ctl.py --wait 10 light 0
ExecStart=/home/fspy/ngenuity2/haste2ctl.py --wait 10 light '#ff8800'
ExecStart=/home/fspy/ngenuity2/haste2ctl.py --wait 10 polling 8000
```

Then `sudo systemctl daemon-reload`.

`--wait` matters: udev fires per-interface as they enumerate, so the vendor
interface may not exist yet when the rule matches.

Check it fired:

```bash
systemctl start haste2ctl.service
journalctl -u haste2ctl.service -n 5
```

**Hyprland `exec-once`.** Simpler, but only runs once per session — unplug the
mouse mid-session and the setting is gone until you log out and back in.

```lua
-- ~/.config/hypr/autostart.lua
Hyprland.exec("/home/fspy/ngenuity2/haste2ctl.py light off")
```

**Polling — removed.** There used to be a `guard` subcommand that re-applied
brightness every `--interval` seconds. It was deleted rather than hardened,
because it was the weaker option on every axis:

- it was a *timer*, not an event hook, so it never detected a reconnect — it
  just rewrote the value whether or not anything had changed
- it had no locking, so two instances raced (this produced phantom `MISMATCH`
  results during development)
- it overwrote any `color` setting, since a `40 01` write replaces the
  direct-lighting mode

If you need a timer anyway, `systemd` `Restart=always` on the oneshot unit is
strictly better: it gets a real lifecycle, journalling and no polling.

### LED zones and the DPI indicator

The mouse has one addressable LED slot, not one per physical LED. Verified on
hardware: brightness 0 extinguishes the DPI stage indicator as well as the logo
and wheel, while DPI stage switching itself keeps working normally.

The distinction is *where each piece of state lives*:

| Function | Lives in | Affected by brightness 0 |
|---|---|---|
| DPI stage switching | firmware, triggered by the button | still works |
| Per-stage indicator colour | onboard flash, written by NGENUITY | still stored, just not emitted |
| Logo / wheel lighting | firmware, driven by the host brightness register | off |

So the per-stage colours are firmware-side state, not host-addressable LEDs.
Brightness 0 mutes the output path only — it does not desync or erase the
NGENUITY configuration, and raising brightness brings the colours straight back.

The corollary is that there is no way to keep the DPI indicator lit while
turning the main lighting off: the host gets one global brightness register
covering every LED, and the firmware multiplexes its own internal colour
sources through it.

### Brightness and colour interact

`40 02` reads a real brightness register. A direct RGB frame
(`light '#rrggbb'`) pins it to `0xFF` until a `40 01` write replaces it, so
brightness and colour are two distinct lighting paths, not layers of one:

```
light 64         -> 0x40
light '#ff0000'  -> 0xFF   (frame forces full brightness)
light 64         -> 0x40   (40 01 takes over again)
```

**Gotcha:** the firmware *silently drops* a `40 01` brightness write that
arrives immediately after a colour frame — the frame has to settle first. A
brightness write in the same breath as a colour frame is ACKed (`result 0x00`)
and then ignored, so the readback disagrees with what you asked for. The tool
retries once on a brightness write for this reason; it is a device quirk, not
a protocol error, and it only bites within a single process — two separate
`haste2ctl` invocations are always far enough apart.

## Tests

```bash
./test_units.py    # pure helpers, no device needed
./test_cli.py      # golden-output CLI test against the live mouse
```

`test_units.py` covers the arithmetic — DPI code round trips against values
read from the real mouse, the `Hz = 8000/RR` table, mask construction, stage
offsets, argument disambiguation. `test_cli.py` runs the CLI and compares
output, but normalises your own settings (brightness, polling rate, stage
values, indicator colours, active stage) because those are device state rather
than tool behaviour. Mutate the mouse freely and the suite still passes; the
mutating cases restore what they change.


