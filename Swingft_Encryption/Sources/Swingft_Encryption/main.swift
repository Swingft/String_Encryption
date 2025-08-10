import Foundation
import SwiftSyntax
import SwiftParser

final class EmptyStringLineCollector: SyntaxVisitor {
    private let filePath: String
    private(set) var lines: [Int] = []

    init(filePath: String) {
        self.filePath = filePath
        super.init(viewMode: .sourceAccurate)
    }

    override func visit(_ node: StringLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        let value = node.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty {
            let ln = SourceLoc.line(of: node, filePath: filePath)
            lines.append(ln)
        }
        return .skipChildren
    }
}

func collectSwiftFiles(in directory: URL) -> [URL] {
    var swiftFiles: [URL] = []

    let fileManager = FileManager.default
    guard let enumerator = fileManager.enumerator(at: directory, includingPropertiesForKeys: nil) else {
        return []
    }

    for case let fileURL as URL in enumerator {
        let path = fileURL.path
        let components = path.split(separator: "/")
        guard components.allSatisfy({ !$0.hasPrefix(".") }) else { continue }

        if fileURL.pathExtension == "swift" {
            swiftFiles.append(fileURL)
        }
    }

    return swiftFiles
}

func saveToText(entries: [(String, String)], outputPath: String) {
    let lines = entries.map { "\($0.0) -> \($0.1)" }
    let joined = lines.joined(separator: "\n")
    do {
        try joined.write(toFile: outputPath, atomically: true, encoding: .utf8)
        print("Saved to \(outputPath)")
    } catch {
        print(" Failed to save to file: \(error)")
    }
}

guard CommandLine.arguments.count >= 3 else {
    print("Usage: swift run <tool> <source-directory> <config-json-path>")
    exit(1)
}

let sourcePath = CommandLine.arguments[1]
let configPath = CommandLine.arguments[2]

let sourceURL = URL(fileURLWithPath: sourcePath)
let swiftFiles = collectSwiftFiles(in: sourceURL)
var allEntries: [(String, String)] = []

let config = ConfigLoader.loadConfig(from: configPath)
let excludedKeywords = config?.shouldEncryptStrings == true ? config?.encryptionExcludes ?? [] : []

for fileURL in swiftFiles {
    let file = fileURL.path
    guard let source = try? String(contentsOfFile: file) else { continue }

    let tree = Parser.parse(source: source)

    let globalVisitor = GlobalStringCollector(viewMode: .sourceAccurate, filePath: file)
    globalVisitor.walk(tree)
    allEntries.append(contentsOf: globalVisitor.globalStrings.map { ("STR: \($0.0)", $0.1) })

    let entryVisitor = EntryPointStringExtractor(viewMode: .sourceAccurate, filePath: file)
    entryVisitor.walk(tree)
    allEntries.append(contentsOf: entryVisitor.entryPointStrings.map { ("STR: \($0.0)", $0.1) })

    let debugVisitor = DebugStringExtractor(viewMode: .sourceAccurate, filePath: file)
    debugVisitor.walk(tree)
    allEntries.append(contentsOf: debugVisitor.debugStrings.map { ("STR: \($0.0)", $0.1) })

    let idVisitor = IdentifierStringExtractor(viewMode: .sourceAccurate, filePath: file)
    idVisitor.walk(tree)
    allEntries.append(contentsOf: idVisitor.identifierStrings.map { ("STR: \($0.0)", $0.1) })

    let constVisitor = ConstantNumberExtractor(viewMode: .sourceAccurate, filePath: file)
    constVisitor.walk(tree)
    allEntries.append(contentsOf: constVisitor.constants)

    let localizedExtractor = LocalizedStringExtractor(filePath: file)
    localizedExtractor.walk(tree)
    allEntries.append(contentsOf: localizedExtractor.excludedStrings.map { ("STR: \($0.0)", $0.1) })

    let attributeMatches = AttributeStringExtractor.extract(from: source)
    allEntries.append(contentsOf: attributeMatches.map {
        let (text, line) = ($0.0, $0.1)
        return ("STR: \(file):\(line)", "\"\(text)\"")
    })

    let lresExtractor = LocalizedStringResourceExtractor(filePath: file, source: source)
    lresExtractor.walk(tree)
    allEntries.append(contentsOf: lresExtractor.resources.map { ("STR: \($0.0)", $0.1) })

    let emptyCollector = EmptyStringLineCollector(filePath: file)
    emptyCollector.walk(tree)
    allEntries.append(contentsOf: emptyCollector.lines.map { ("STR: \(file):\($0)", "\"\"") })


    let contextExtractor = ContextStringExtractor(viewMode: .sourceAccurate, filePath: file)
    contextExtractor.walk(tree)
    allEntries.append(contentsOf: contextExtractor.excludedStrings.map { ("STR: \($0.0)", $0.1) })


    if !excludedKeywords.isEmpty {
        let matched = ConfigLoader.extractExcludedStrings(from: source, filePath: file, excludedList: excludedKeywords)
        allEntries.append(contentsOf: matched.map { ("STR: \($0.0)", $0.1) })
    }
}

func sortEntriesByFileAndLine(_ entries: [(String, String)]) -> [(String, String)] {
    let rx = try! NSRegularExpression(pattern: #"^STR:\s*(.+?\.swift):(\d+)\s*->"#)
    func parts(_ key: String) -> (String, Int)? {
        let ns = key as NSString
        guard let m = rx.firstMatch(in: key, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges >= 3
        else { return nil }
        let file = ns.substring(with: m.range(at: 1))
        let line = Int(ns.substring(with: m.range(at: 2))) ?? 0
        return (file, line)
    }
    return entries.sorted { a, b in
        guard let pa = parts(a.0), let pb = parts(b.0) else { return a.0 < b.0 }
        return pa.0 == pb.0 ? (pa.1 < pb.1) : (pa.0 < pb.0)
    }
}


let sorted = sortEntriesByFileAndLine(allEntries)
saveToText(entries: sorted, outputPath: "excluded_String.txt")


let pythonScriptPath = "./SwingftEncryption.py"
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
process.arguments = [pythonScriptPath, sourcePath, "excluded_String.txt"]
let pipe = Pipe()
process.standardOutput = pipe
process.standardError = pipe

do {
    try process.run()
    process.waitUntilExit()

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    if let output = String(data: data, encoding: .utf8) {
        print("Python script output:\n\(output)")
    }
} catch {
    print("Python script execution failed: \(error)")
}
