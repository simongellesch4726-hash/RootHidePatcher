//
//  ShellScript.swift
//  Derootifier
//

import UIKit
import Foundation

private enum FixedPathRewriter {
    private static let pageSize: UInt64 = 0x4000

    // Rootfs/user-data paths stay physical. /var/mobile is especially
    // important: tweak preferences belong to the user data root, not jbroot.
    private static let excludedPrefixes = [
        "/var/mobile/",
        "/var/containers/",
        "/var/run/",
        "/var/db/",
        "/var/root/",
        "/var/empty/"
    ]

    private struct CString {
        let fileOffset: Int
        let address: UInt64
        let value: String
    }

    private struct Relocation {
        let old: CString
        let replacement: String
        var newAddress: UInt64 = 0
    }

    private struct Segment {
        let commandOffset: Int
        let vmaddr: UInt64
        let vmsize: UInt64
        let fileoff: UInt64
        let filesize: UInt64
        let nsects: UInt32
    }

    private struct Section {
        let addr: UInt64
        let size: UInt64
        let offset: UInt32
    }

    private struct RewriteResult {
        let data: Data
        let changed: Int
    }

    static func preprocessRootlessPackage(_ deb: URL) -> URL? {
        let fm = FileManager.default
        let base = jbroot("/var/mobile/RootHidePatcher/.fixed-paths-\(UUID().uuidString)")
        let staged = base + "/pkg"
        let patchedDeb = base + "/patched.deb"

        do {
            try fm.createDirectory(atPath: staged, withIntermediateDirectories: true)
            defer { try? fm.removeItem(atPath: base) }

            let dpkg = jbroot("/usr/bin/dpkg-deb")
            guard run(dpkg, ["-R", deb.path, staged]) else {
                NSLog("RootHidePatcher: fixed-path preprocessing: extract failed")
                return nil
            }

            let count = rewriteTree(URL(fileURLWithPath: staged))
            guard count > 0 else { return nil }

            guard run(dpkg, ["-b", staged, patchedDeb]) else {
                NSLog("RootHidePatcher: fixed-path preprocessing: repack failed")
                return nil
            }

            let persistent = jbroot("/var/mobile/RootHidePatcher/.fixed-paths-\(UUID().uuidString).deb")
            try fm.copyItem(atPath: patchedDeb, toPath: persistent)
            return URL(fileURLWithPath: persistent)
        } catch {
            NSLog("RootHidePatcher: fixed-path preprocessing failed: \(error)")
            return nil
        }
    }

    private static func run(_ command: String, _ args: [String]) -> Bool {
        let receipt = AuxiliaryExecute.spawn(command: command, args: args, environment: nil, output: { _ in })
        return receipt.exitCode == 0
    }

    private static func rewriteTree(_ root: URL) -> Int {
        var changed = 0
        guard let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) else {
            return 0
        }

        for case let url as URL in e {
            if url.path.contains("/DEBIAN/") { continue }
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue { continue }
            guard let data = try? Data(contentsOf: url), isMachO(data) else { continue }

            do {
                let result = try rewriteMachO(data)
                if result.changed > 0 {
                    try result.data.write(to: url, options: .atomic)
                    changed += result.changed
                }
            } catch {
                // A binary with an unsupported layout is left untouched.
                // The existing fixed-path warning remains responsible for
                // surfacing it.
                NSLog("RootHidePatcher: fixed-path rewriter skipped %@: %@", url.path, String(describing: error))
            }
        }
        return changed
    }

    private static func rewriteMachO(_ data: Data) throws -> RewriteResult {
        let magic = read32(data, 0)
        if magic == 0xcafebabe {
            return try rewriteFat(data)
        }
        guard magic == 0xfeedfacf else {
            return RewriteResult(data: data, changed: 0)
        }
        return try rewriteThin(data)
    }

    private static func rewriteFat(_ data: Data) throws -> RewriteResult {
        let count = Int(read32BE(data, 4))
        guard count > 0, 8 + count * 20 <= data.count else { return RewriteResult(data: data, changed: 0) }

        var slices: [(cpu: UInt32, subtype: UInt32, align: UInt32, data: Data)] = []
        var changed = 0

        for i in 0..<count {
            let p = 8 + i * 20
            let cpu = read32BE(data, p)
            let subtype = read32BE(data, p + 4)
            let off = Int(read32BE(data, p + 8))
            let size = Int(read32BE(data, p + 12))
            let align = read32BE(data, p + 16)
            guard off >= 0, size >= 0, off + size <= data.count else { throw NSError(domain: "FixedPathRewriter", code: 1) }

            let result = try rewriteMachO(data.subdata(in: off..<(off + size)))
            slices.append((cpu, subtype, align, result.data))
            changed += result.changed
        }

        guard changed > 0 else { return RewriteResult(data: data, changed: 0) }

        var out = Data(count: 8 + count * 20)
        write32BE(&out, 0, 0xcafebabe)
        write32BE(&out, 4, UInt32(count))

        var offset = UInt64(out.count)
        for i in 0..<count {
            let s = slices[i]
            let alignment = UInt64(1) << min(s.align, 30)
            offset = alignUp(offset, alignment)
            if out.count < Int(offset) {
                out.append(Data(repeating: 0, count: Int(offset) - out.count))
            }
            out.append(s.data)

            let p = 8 + i * 20
            write32BE(&out, p, s.cpu)
            write32BE(&out, p + 4, s.subtype)
            write32BE(&out, p + 8, UInt32(offset))
            write32BE(&out, p + 12, UInt32(s.data.count))
            write32BE(&out, p + 16, s.align)
            offset += UInt64(s.data.count)
        }

        return RewriteResult(data: out, changed: changed)
    }

    private static func rewriteThin(_ input: Data) throws -> RewriteResult {
        var data = input
        guard read32(data, 0) == 0xfeedfacf else { return RewriteResult(data: data, changed: 0) }

        let ncmds = Int(read32(data, 16))
        var cstrings: Section?
        var cfstrings: Section?
        var globalData: Section?
        var executableSegments: [Segment] = []
        var linkedit: Segment?

        var lc = 32
        for _ in 0..<ncmds {
            guard lc + 8 <= data.count else { throw NSError(domain: "FixedPathRewriter", code: 2) }
            let cmd = read32(data, lc)
            let cmdsize = Int(read32(data, lc + 4))
            guard cmdsize >= 8, lc + cmdsize <= data.count else { throw NSError(domain: "FixedPathRewriter", code: 3) }

            if cmd == 0x19 { // LC_SEGMENT_64
                let name = readCString(data, lc + 8, 16)
                let seg = Segment(
                    commandOffset: lc,
                    vmaddr: read64(data, lc + 24),
                    vmsize: read64(data, lc + 32),
                    fileoff: read64(data, lc + 40),
                    filesize: read64(data, lc + 48),
                    nsects: read32(data, lc + 64)
                )

                if name == "__LINKEDIT" { linkedit = seg }
                if (read32(data, lc + 60) & 0x4) != 0 { executableSegments.append(seg) }

                var sp = lc + 72
                for _ in 0..<Int(seg.nsects) {
                    guard sp + 80 <= lc + cmdsize else { throw NSError(domain: "FixedPathRewriter", code: 4) }
                    let sec = Section(addr: read64(data, sp + 32), size: read64(data, sp + 40), offset: read32(data, sp + 48))
                    let secName = readCString(data, sp, 16)
                    let segName = readCString(data, sp + 16, 16)

                    if segName == "__TEXT" && secName == "__cstring" { cstrings = sec }
                    if (segName == "__DATA" || segName == "__DATA_CONST") && secName == "__cfstring" { cfstrings = sec }
                    if segName == "__DATA" && secName == "__data" { globalData = sec }
                    sp += 80
                }
            }
            lc += cmdsize
        }

        guard let csec = cstrings, let le = linkedit else {
            return RewriteResult(data: data, changed: 0)
        }

        let strings = scanStrings(data, csec)
        var inPlace: [(CString, String)] = []
        var relocations: [Relocation] = []

        for s in strings {
            guard let replacement = convertedPath(s.value), replacement != s.value else { continue }
            if replacement.utf8.count <= s.value.utf8.count {
                inPlace.append((s, replacement))
            } else {
                relocations.append(Relocation(old: s, replacement: replacement))
            }
        }

        for (s, replacement) in inPlace {
            replaceBytes(&data, at: s.fileOffset, oldLength: s.value.utf8.count, with: replacement)
        }

        guard !relocations.isEmpty else {
            return RewriteResult(data: data, changed: inPlace.count)
        }

        // __LINKEDIT is normally the final file-backed segment. Appending
        // there lets us grow strings without inserting a new load command.
        let linkeditEnd = Int(le.fileoff + le.filesize)
        guard linkeditEnd == data.count else {
            throw NSError(domain: "FixedPathRewriter", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "non-final __LINKEDIT"])
        }

        var appended = Data()
        for i in relocations.indices {
            relocations[i].newAddress = le.vmaddr + le.filesize + UInt64(appended.count)
            appended.append(contentsOf: relocations[i].replacement.utf8)
            appended.append(0)
        }

        data.append(appended)
        write64(&data, le.commandOffset + 48, le.filesize + UInt64(appended.count))
        write64(&data, le.commandOffset + 32, alignUp(le.filesize + UInt64(appended.count), pageSize))

        var targets: [UInt64: Relocation] = [:]
        for r in relocations { targets[r.old.address] = r }

        patchCFStrings(&data, cfstrings, targets)
        patchGlobalStrings(&data, globalData, targets)
        patchInstructionReferences(&data, executableSegments, targets)

        return RewriteResult(data: data, changed: inPlace.count + relocations.count)
    }

    private static func scanStrings(_ data: Data, _ section: Section) -> [CString] {
        let start = Int(section.offset)
        let end = min(data.count, start + Int(section.size))
        guard start >= 0, start < end else { return [] }

        var result: [CString] = []
        var p = start
        while p < end {
            let q = data[p..<end].firstIndex(of: 0) ?? end
            if q > p {
                result.append(CString(fileOffset: p, address: section.addr + UInt64(p - start),
                                      value: String(decoding: data[p..<q], as: UTF8.self)))
            }
            p = q + 1
        }
        return result
    }

    private static func patchCFStrings(_ data: inout Data, _ section: Section?, _ targets: [UInt64: Relocation]) {
        guard let section else { return }
        let start = Int(section.offset)
        let end = min(data.count, start + Int(section.size))
        var p = start

        while p + 32 <= end {
            let old = read64(data, p + 16)
            if let r = targets[old] {
                write64(&data, p + 16, r.newAddress)
                write64(&data, p + 24, UInt64(r.replacement.utf8.count))
            }
            p += 32
        }
    }

    private static func patchGlobalStrings(_ data: inout Data, _ section: Section?, _ targets: [UInt64: Relocation]) {
        guard let section else { return }
        let start = Int(section.offset)
        let end = min(data.count, start + Int(section.size))
        var p = start

        while p + 8 <= end {
            let old = read64(data, p)
            if let r = targets[old] { write64(&data, p, r.newAddress) }
            p += 8
        }
    }

    private static func patchInstructionReferences(_ data: inout Data, _ segments: [Segment], _ targets: [UInt64: Relocation]) {
        var regs = [UInt64](repeating: 0, count: 32)

        for seg in segments {
            let start = Int(seg.fileoff)
            let end = min(data.count, start + Int(seg.filesize))
            guard start >= 0, start < end else { continue }

            var p = start
            while p + 4 <= end {
                let pc = seg.vmaddr + UInt64(p - start)
                let insn = read32(data, p)

                if (insn & 0x9f000000) == 0x90000000 { // ADRP
                    let immlo = Int64((insn >> 29) & 3)
                    let immhi = Int64((insn >> 5) & 0x7ffff)
                    var imm = (immhi << 2) | immlo
                    if (imm & (1 << 20)) != 0 { imm -= 1 << 21 }
                    regs[Int(insn & 31)] = UInt64(Int64(pc & ~0xfff) + (imm << 12))
                } else if (insn & 0xff000000) == 0x91000000 { // ADD immediate
                    let rn = Int((insn >> 5) & 31)
                    let rd = Int(insn & 31)
                    let shift = (insn >> 22) & 3
                    if shift <= 1 {
                        let imm = UInt64((insn >> 10) & 0xfff) << (shift == 1 ? 12 : 0)
                        regs[rd] = regs[rn] &+ imm

                        if let r = targets[regs[rd]], p >= start + 4 {
                            let prev = read32(data, p - 4)
                            if (prev & 0x9f000000) == 0x90000000 && Int(prev & 31) == rn {
                                let pageDelta = Int64(r.newAddress >> 12) - Int64(pc >> 12)
                                write32(&data, p - 4, encodeADRP(rd: rn, pageDelta: pageDelta))
                                write32(&data, p, encodeADD(rd: rd, rn: rn, immediate: UInt32(r.newAddress & 0xfff)))
                            }
                        }
                    }
                } else if (insn & 0x9f000000) == 0x10000000 { // ADR
                    let rd = Int(insn & 31)
                    var imm = Int64(((insn >> 29) & 3) | (((insn >> 5) & 0x7ffff) << 2))
                    if (imm & (1 << 20)) != 0 { imm -= 1 << 21 }
                    let oldAddress = UInt64(Int64(pc) + imm)

                    if let r = targets[oldAddress] {
                        let delta = Int64(r.newAddress) - Int64(pc)
                        if delta >= -0x100000 && delta <= 0xFFFFF {
                            write32(&data, p, encodeADR(rd: rd, delta: delta))
                            patchSwiftLength(&data, p + 16, oldLength: r.old.value.utf8.count, newLength: r.replacement.utf8.count)
                        } else if p + 8 <= end && read32(data, p + 4) == 0xd503201f {
                            write32(&data, p, encodeADRP(rd: rd, pageDelta: Int64(r.newAddress >> 12) - Int64(pc >> 12)))
                            write32(&data, p + 4, encodeADD(rd: rd, rn: rd, immediate: UInt32(r.newAddress & 0xfff)))
                            patchSwiftLength(&data, p + 16, oldLength: r.old.value.utf8.count, newLength: r.replacement.utf8.count)
                        }
                    }
                }
                p += 4
            }
        }
    }

    private static func patchSwiftLength(_ data: inout Data, _ offset: Int, oldLength: Int, newLength: Int) {
        guard offset + 4 <= data.count else { return }
        let insn = read32(data, offset)
        guard (insn & 0xff800000) == 0xd2800000 else { return }
        guard Int((insn >> 5) & 0xffff) == oldLength else { return }
        write32(&data, offset, (insn & 0xffe0001f) | (UInt32(newLength & 0xffff) << 5))
    }

    private static func convertedPath(_ s: String) -> String? {
        guard s.hasPrefix("/") else { return nil }
        if s.hasPrefix("/var/jb/") || s == "/var/jb" { return nil }
        if excludedPrefixes.contains(where: { s.hasPrefix($0) }) { return nil }

        var value = s
        if value.hasPrefix("/private/var/") {
            value = "/" + String(value.dropFirst("/private/".count))
        }
        if value.hasPrefix("/var/tmp") {
            value = "/tmp" + String(value.dropFirst("/var/tmp".count))
        }
        guard value.hasPrefix("/var/") || value == "/var" else { return nil }
        return "/var/jb" + value
    }

    private static func isMachO(_ data: Data) -> Bool {
        let m = read32(data, 0)
        return m == 0xfeedfacf || m == 0xcafebabe
    }

    private static func alignUp(_ value: UInt64, _ alignment: UInt64) -> UInt64 {
        (value + alignment - 1) & ~(alignment - 1)
    }

    private static func readCString(_ data: Data, _ offset: Int, _ length: Int) -> String {
        guard offset >= 0, offset + length <= data.count else { return "" }
        let end = data[offset..<(offset + length)].firstIndex(of: 0) ?? offset + length
        return String(decoding: data[offset..<end], as: UTF8.self)
    }

    private static func read32(_ d: Data, _ o: Int) -> UInt32 {
        guard o >= 0, o + 4 <= d.count else { return 0 }
        var v: UInt32 = 0
        for i in 0..<4 { v |= UInt32(d[o + i]) << UInt32(i * 8) }
        return v
    }

    private static func read64(_ d: Data, _ o: Int) -> UInt64 {
        guard o >= 0, o + 8 <= d.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(d[o + i]) << UInt64(i * 8) }
        return v
    }

    private static func read32BE(_ d: Data, _ o: Int) -> UInt32 {
        var v: UInt32 = 0
        for i in 0..<4 { v = (v << 8) | UInt32(d[o + i]) }
        return v
    }

    private static func write32(_ d: inout Data, _ o: Int, _ v: UInt32) {
        guard o >= 0, o + 4 <= d.count else { return }
        for i in 0..<4 { d[o + i] = UInt8((v >> UInt32(i * 8)) & 0xff) }
    }

    private static func write64(_ d: inout Data, _ o: Int, _ v: UInt64) {
        guard o >= 0, o + 8 <= d.count else { return }
        for i in 0..<8 { d[o + i] = UInt8((v >> UInt64(i * 8)) & 0xff) }
    }

    private static func write32BE(_ d: inout Data, _ o: Int, _ v: UInt32) {
        guard o >= 0, o + 4 <= d.count else { return }
        for i in 0..<4 { d[o + i] = UInt8((v >> UInt32(24 - i * 8)) & 0xff) }
    }

    private static func replaceBytes(_ d: inout Data, at offset: Int, oldLength: Int, with string: String) {
        let bytes = Array(string.utf8)
        guard offset >= 0, offset + oldLength <= d.count else { return }
        for i in 0..<oldLength { d[offset + i] = i < bytes.count ? bytes[i] : 0 }
    }

    private static func encodeADR(rd: Int, delta: Int64) -> UInt32 {
        let imm = UInt64(bitPattern: delta) & 0x1fffff
        return 0x10000000 | UInt32((imm & 3) << 29) | UInt32(((imm >> 2) & 0x7ffff) << 5) | UInt32(rd)
    }

    private static func encodeADRP(rd: Int, pageDelta: Int64) -> UInt32 {
        let imm = UInt64(bitPattern: pageDelta) & 0x1fffff
        return 0x90000000 | UInt32((imm & 3) << 29) | UInt32(((imm >> 2) & 0x7ffff) << 5) | UInt32(rd)
    }

    private static func encodeADD(rd: Int, rn: Int, immediate: UInt32) -> UInt32 {
        0x91000000 | ((immediate & 0xfff) << 10) | (UInt32(rn) << 5) | UInt32(rd)
    }
}

func repackDeb(scriptPath: String, debURL: URL, outputURL: URL, patch: String) -> (Int,String) {
    var output = ""
    let command = jbroot("/usr/bin/bash")
    let env = ["PATH": "/usr/bin:$PATH:\(rootfs(Bundle.main.bundlePath))/cctools"]

    var inputURL = debURL
    var temporaryInput: URL?

    // Only Rootless Compat gets the fixed-path rewrite. DynamicPatches and
    // direct conversion are deliberately untouched.
    if patch == "AutoPatches", let preprocessed = FixedPathRewriter.preprocessRootlessPackage(debURL) {
        inputURL = preprocessed
        temporaryInput = preprocessed
    }

    let args = ["-p", rootfs(scriptPath), inputURL.path, outputURL.path, patch]

    NSLog("RootHidePatcher: uid=\(getuid()) euid=\(geteuid()) gid=\(getgid())")
    let receipt = AuxiliaryExecute.spawn(command: command, args: args, environment: env, output: { output += $0 })

    if let temporaryInput {
        try? FileManager.default.removeItem(at: temporaryInput)
    }

    return (receipt.exitCode, output)
}

func folderCheck() {
    do {
        if FileManager.default.fileExists(atPath: jbroot("/var/mobile/RootHidePatcher/.Inbox")) {
            print("We're good! :)")
        } else {
            try FileManager.default.createDirectory(atPath: jbroot("/var/mobile/RootHidePatcher/.Inbox"), withIntermediateDirectories: true)
        }
    } catch {
        UIApplication.shared.alert(title: "Error!", body: "There was a problem with making the folder for the deb.", withButton: false)
    }
}

func checkFileMngrs(path: String) {
    NSLog("RootHidePatcher: \(path)")
    let activity = UIActivityViewController(activityItems: [URL(fileURLWithPath: jbroot(path))], applicationActivities: nil)
    
    let window = UIApplication.shared.keyWindow!

    activity.popoverPresentationController?.sourceView = window
    activity.popoverPresentationController?.sourceRect = CGRect(x: window.bounds.midX, y: window.bounds.height, width: 0, height: 0)
    activity.popoverPresentationController?.permittedArrowDirections = UIPopoverArrowDirection.down
    
    UIApplication.shared.present(alert: activity)
}
