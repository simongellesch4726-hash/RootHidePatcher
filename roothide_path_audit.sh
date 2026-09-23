#!/bin/bash
#
# RootHidePatcher automatic filesystem-path audit.
#
# This helper deliberately does NOT rewrite Mach-O string data. A literal
# filesystem path is not enough to determine whether the value is consumed as
# a rootfs path, a jbroot path, or persisted for later use.
#
# Exit status:
#   0 = no RootHide-sensitive candidates
#   1 = candidates found
#
# Output format:
#   TYPE<TAB>PATH
#
# "jbroot" candidates are paths that are conventionally part of the jailbreak
# namespace. Rootfs/user-data paths are explicitly excluded.

set -e

FILE="$1"
[ -n "$FILE" ] || exit 2
[ -f "$FILE" ] || exit 2

case "$(file -b "$FILE" 2>/dev/null || true)" in
    *Mach-O*) ;;
    *) exit 0 ;;
esac

# strings output is used only for discovery. It is never used to mutate the
# Mach-O, avoiding false-positive binary corruption.
strings -a "$FILE" 2>/dev/null |
awk '
function emit(kind, path) {
    if (!(kind SUBSEP path in seen)) {
        print kind "\t" path
        seen[kind SUBSEP path] = 1
        found = 1
    }
}
{
    s=$0

    # Explicit legacy rootless namespace.
    if (s ~ /^\/var\/jb(\/|$)/)
        emit("jbroot", s)

    # Common bootstrap-owned writable namespaces. These are logical jbroot
    # paths under RootHide, unlike /var/mobile and iOS system databases.
    if (s ~ /^\/var\/(tmp|log|cache|lib|empty|config)(\/|$)/)
        emit("jbroot", s)

    # Rootfs/user-data paths must not be blindly converted.
    if (s ~ /^\/var\/(mobile|db|run|folders|containers)(\/|$)/)
        emit("rootfs", s)

    if (s ~ /^\/private\/var\/mobile(\/|$)/)
        emit("rootfs", s)
}
END {
    exit(found ? 1 : 0)
}'
