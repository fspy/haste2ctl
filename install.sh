#!/usr/bin/env bash
#
# Install haste2ctl so the udev-triggered systemd unit can run it.
#
# The unit is a *system* unit, so it has no meaningful home directory to
# reference: it runs as root, %h expands to /root, $HOME is empty, and there
# is no %HOME specifier (it silently becomes hostname+"OME"). So the script
# goes to a system location instead, which is also what makes the unit
# portable between machines.
#
# The repo copy of haste2ctl.py is the source of truth - re-run this after
# changing it.
#
#   sudo ./install.sh            install
#   sudo ./install.sh --uninstall remove

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN=/usr/local/bin/haste2ctl.py
DOC=/usr/local/share/doc/haste2ctl
RULE=/etc/udev/rules.d/99-haste2ctl.rules
UNIT=/etc/systemd/system/haste2ctl.service

if [[ ${1:-} == --uninstall ]]; then
    rm -f "$BIN" "$RULE" "$UNIT"
    rm -rf "$DOC"
    udevadm control --reload-rules
    systemctl daemon-reload
    echo "removed: $BIN $RULE $UNIT $DOC"
    exit 0
fi

install -Dm755 "$SRC/haste2ctl.py"  "$BIN"
install -Dm644 "$SRC/haste2ctl.rules" "$RULE"
install -Dm644 "$SRC/haste2ctl.service" "$UNIT"
install -Dm644 "$SRC/README.md"      "$DOC/README.md"
udevadm control --reload-rules
systemctl daemon-reload

echo "installed:"
echo "  $BIN"
echo "  $RULE"
echo "  $UNIT"
echo "  $DOC/README.md"
echo
echo "check it runs:"
echo "  systemctl start haste2ctl.service && journalctl -u haste2ctl.service -n3"
