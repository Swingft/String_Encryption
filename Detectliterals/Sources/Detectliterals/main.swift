import Foundation
import SwiftSyntax
import SwiftParser

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
        print("Error saving to file: \(error)")
    }
}
guard CommandLine.arguments.count >= 3 else {
    print("Usage: swift run String_Encryption_Excluded <source-directory> <config-json-path>")
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
    allEntries.append(contentsOf: globalVisitor.globalStrings)

    let entryVisitor = EntryPointStringExtractor(viewMode: .sourceAccurate, filePath: file)
    entryVisitor.walk(tree)
    allEntries.append(contentsOf: entryVisitor.entryPointStrings)

    let debugVisitor = DebugStringExtractor(viewMode: .sourceAccurate, filePath: file)
    debugVisitor.walk(tree)
    allEntries.append(contentsOf: debugVisitor.debugStrings)

    let idVisitor = IdentifierStringExtractor(viewMode: .sourceAccurate, filePath: file)
    idVisitor.walk(tree)
    allEntries.append(contentsOf: idVisitor.identifierStrings)

    if !excludedKeywords.isEmpty {
        let matched = ConfigLoader.extractExcludedStrings(from: source, filePath: file, excludedList: excludedKeywords)
        allEntries.append(contentsOf: matched)
    }
}

saveToText(entries: allEntries, outputPath: "excluded_String.txt")
