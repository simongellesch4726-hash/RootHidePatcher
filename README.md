# RootHidePatcher

RootHidePatcher converts rootless `iphoneos-arm64` packages to RootHide `iphoneos-arm64e` packages.

## Automatic filesystem-path handling

The converter's `AutoPatches` path now performs a conservative `/var` audit on every Mach-O after conversion.

It distinguishes common RootHide/jailbreak-owned logical paths such as:

- `/var/jb/...`
- `/var/tmp/...`
- `/var/log/...`
- `/var/cache/...`
- `/var/lib/...`
- `/var/empty/...`
- `/var/config/...`

from paths that are normally rooted in the iOS root filesystem and must **not** be blindly redirected, including:

- `/var/mobile/...`
- `/var/db/...`
- `/var/run/...`
- `/var/folders/...`
- `/var/containers/...`
- `/private/var/mobile/...`

The audit is deliberately non-destructive: it never rewrites Mach-O string data merely because a `/var` string was found. Runtime conversion remains the responsibility of the RootHide compatibility/DynamicPatches layer, because a string's presence does not prove how the binary consumes it.

For `AutoPatches`, the converter continues to attach `AutoPatches.dylib` through the `.roothidepatch` mechanism. This gives the runtime layer the opportunity to perform the actual path conversion without embedding a randomized jailbreak path into the binary.

## Build

The project remains an iOS/Xcode + Theos project. The converter can also run directly through `patch.sh` on a RootHide device.

## License

AuxiliaryExecute - https://github.com/Lakr233/AuxiliaryExecute/blob/main/LICENSE (MIT)

FluidGradient - https://github.com/Cindori/FluidGradient/blob/main/LICENSE (MIT)
