#!/bin/bash
# Conservative RootHide fixed-path analyzer.
# Generates a DynamicPatches-compatible plist beside a Mach-O.
set -e

BIN="$1"
OUT="$2"

if [ -z "$BIN" ] || [ -z "$OUT" ] || [ ! -f "$BIN" ]; then
    echo "usage: $0 <Mach-O> <output.plist>" >&2
    exit 2
fi

OTOOL_ARCH=""
if otool -arch arm64e -h "$BIN" >/dev/null 2>&1; then
    OTOOL_ARCH="-arch arm64e"
elif otool -arch arm64 -h "$BIN" >/dev/null 2>&1; then
    OTOOL_ARCH="-arch arm64"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PATCHES="$TMP/patches"
: > "$PATCHES"

classify() {
    local p="$1"
    case "$p" in
        /var/jb|/var/jb/*|/private/var/jb|/private/var/jb/*)
            echo jbroot ;;
        /var/tmp|/var/tmp/*|/private/var/tmp|/private/var/tmp/*|/var/log|/var/log/*|/private/var/log|/private/var/log/*|/var/cache|/var/cache/*|/private/var/cache|/private/var/cache/*|/var/lib|/var/lib/*|/private/var/lib|/private/var/lib/*|/var/empty|/var/empty/*|/private/var/empty|/private/var/empty/*|/var/config|/var/config/*|/private/var/config|/private/var/config/*)
            echo jbroot ;;
        /var/mobile|/var/mobile/*|/private/var/mobile|/private/var/mobile/*|/var/db|/var/db/*|/private/var/db|/private/var/db/*|/var/run|/var/run/*|/private/var/run|/private/var/run/*|/var/folders|/var/folders/*|/private/var/folders|/private/var/folders/*|/var/containers|/var/containers/*|/private/var/containers|/private/var/containers/*)
            echo rootfs ;;
        *) echo unknown ;;
    esac
}

xml_patch_cstring() {
    local addr="$1" reg="$2" action="$3"
    cat >> "$PATCHES" <<EOF
    <dict>
      <key>vaddr</key><integer>$((addr))</integer>
      <key>regs</key><array><integer>$reg</integer></array>
      <key>type</key><string>cstring</string>
      <key>action</key><string>$action</string>
    </dict>
EOF
}

xml_patch_cfstring() {
    local addr="$1" action="$2"
    cat >> "$PATCHES" <<EOF
    <dict>
      <key>vaddr</key><integer>$((addr))</integer>
      <key>type</key><string>__CFString</string>
      <key>action</key><string>$action</string>
    </dict>
EOF
}

# otool prints __cstring entries as: 0xADDRESS STRING.
cstring_dump="$(otool $OTOOL_ARCH -v -s __TEXT __cstring "$BIN" 2>/dev/null || true)"
if [ -z "$cstring_dump" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' '<plist version="1.0"><array></array></plist>' > "$OUT"
    exit 0
fi

DISASM="$TMP/disasm"
otool $OTOOL_ARCH -t -v -V "$BIN" > "$DISASM" 2>/dev/null || true

while IFS= read -r line; do
    case "$line" in
        0x*) ;;
        *) continue ;;
    esac

    addr_token="${line%%[[:space:]]*}"
    path="${line#*[[:space:]]}"
    case "$path" in
        /var/*|/private/var/*) ;;
        *) continue ;;
    esac

    action="$(classify "$path")"
    [ "$action" = "unknown" ] && continue

    addr_dec=$((addr_token))
    page=$((addr_dec & ~0xfff))
    off=$((addr_dec & 0xfff))
    page_hex="$(printf '0x%X' "$page")"
    off_hex="$(printf '0x%X' "$off")"

    # Direct ADRP + ADD materialization. The patch is installed at the
    # instruction immediately after ADD, when the register contains the
    # complete C-string pointer, matching RootHide's documented workflow.
    prev_reg=""
    while IFS= read -r ins; do
        ins_addr="${ins%%[[:space:]]*}"
        ins_addr_dec=$((16#$ins_addr))
        rest="${ins#*[[:space:]]}"
        if printf '%s\n' "$rest" | grep -Eq "^[[:space:]]*adrp[[:space:]]+x([0-9]+),.*;[[:space:]]*$page_hex$"; then
            prev_reg="$(printf '%s\n' "$rest" | sed -nE 's/^[[:space:]]*adrp[[:space:]]+x([0-9]+),.*;[[:space:]]*0x[0-9a-fA-F]+$/\1/p')"
            continue
        fi
        if [ -n "$prev_reg" ]; then
            add_reg="$(printf '%s\n' "$rest" | sed -nE 's/^[[:space:]]*add[[:space:]]+x([0-9]+),[[:space:]]*x([0-9]+),[[:space:]]*#?0x?([0-9a-fA-F]+).*$/\1 \2 \3/p')"
            if [ -n "$add_reg" ]; then
                set -- $add_reg
                dst="$1"; src="$2"; imm="$3"
                if [ "$src" = "$prev_reg" ] && [ $((16#$imm)) -eq "$off" ]; then
                    patch_addr=$((ins_addr_dec + 4))
                    xml_patch_cstring "$patch_addr" "$dst" "$action"
                fi
            fi
            prev_reg=""
        fi
    done < "$DISASM"

    # Direct ADR materialization.
    while IFS= read -r ins; do
        ins_addr="${ins%%[[:space:]]*}"
        ins_addr_dec=$((16#$ins_addr))
        rest="${ins#*[[:space:]]}"
        target="$(printf '%s\n' "$rest" | sed -nE 's/^[[:space:]]*adr[[:space:]]+x([0-9]+),[[:space:]]*0x([0-9a-fA-F]+).*$/\2/p')"
        if [ -n "$target" ] && [ $((16#$target)) -eq "$addr_dec" ]; then
            reg="$(printf '%s\n' "$rest" | sed -nE 's/^[[:space:]]*adr[[:space:]]+x([0-9]+),.*/\1/p')"
            [ -n "$reg" ] && xml_patch_cstring $((ins_addr_dec + 4)) "$reg" "$action"
        fi
    done < "$DISASM"

    # __CFString constants reference the same __cstring address in their
    # buffer field. Support both DATA layouts used by modern Mach-O files.
    for seg in __DATA __DATA_CONST; do
        cf="$(otool $OTOOL_ARCH -v -s "$seg" __cfstring "$BIN" 2>/dev/null || true)"
        [ -z "$cf" ] && continue
        while IFS= read -r cfl; do
            if printf '%s\n' "$cfl" | grep -Fqi "$addr_token"; then
                cfaddr="${cfl%%[[:space:]]*}"
                case "$cfaddr" in
                    0x*) xml_patch_cfstring "$((cfaddr))" "$action" ;;
                esac
            fi
        done <<EOF_CF
$cf
EOF_CF
    done
done <<EOF_STRINGS
$cstring_dump
EOF_STRINGS

# Deduplicate identical dictionaries by normalizing through plutil.
# If no patches were discovered, emit a valid empty array.
if [ ! -s "$PATCHES" ]; then
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' '<plist version="1.0"><array></array></plist>' > "$OUT"
    exit 0
fi

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><array>'
    cat "$PATCHES"
    echo '</array></plist>'
} > "$OUT"

if command -v plutil >/dev/null 2>&1; then
    plutil -convert binary1 "$OUT" >/dev/null 2>&1 || true
fi

echo "generated fixed-path patch configuration: $OUT"
