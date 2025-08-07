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
    allEntries.append(contentsOf: attributeMatches.map { ("STR", "\(file) -> \"\($0.0)\"") })
    
    let labeledExtractor = LabeledArgumentStringExtractor(viewMode: .sourceAccurate, filePath: file)
    labeledExtractor.walk(tree)
    allEntries.append(contentsOf: labeledExtractor.excludedStrings.map { ("STR: \($0.0)", $0.1) })

    if !excludedKeywords.isEmpty {
        let matched = ConfigLoader.extractExcludedStrings(from: source, filePath: file, excludedList: excludedKeywords)
        allEntries.append(contentsOf: matched.map { ("STR: \($0.0)", $0.1) })
    }
}

saveToText(entries: allEntries, outputPath: "excluded_String.txt")

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
