import Foundation
import SwiftSyntax
import SwiftParser

struct LiteralEntry: Codable {
    let file: String
    let line: Int
    let literal: String
    let type: String
}

class LiteralExtractor: SyntaxVisitor {
    var literals: [LiteralEntry] = []
    var currentFile: String = ""
    var sourceLines: [String] = []

    override func visit(_ node: IntegerLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        let pos = node.positionAfterSkippingLeadingTrivia
        let line = lineNumber(at: pos)
        literals.append(LiteralEntry(file: currentFile, line: line, literal: node.literal.text, type: "Int"))
        return .skipChildren
    }

    override func visit(_ node: StringLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        let raw = node.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let pos = node.positionAfterSkippingLeadingTrivia
        let line = lineNumber(at: pos)
        literals.append(LiteralEntry(file: currentFile, line: line, literal: raw, type: "String"))
        return .skipChildren
    }


    func lineNumber(at pos: AbsolutePosition) -> Int {
        let utf8Offset = pos.utf8Offset
        var count = 1
        var offset = 0
        for line in sourceLines {
            offset += line.utf8.count + 1
            if offset > utf8Offset {
                break
            }
            count += 1
        }
        return count
    }
}

func collectSwiftFiles(in directory: URL) -> [URL] {
    let fm = FileManager.default
    guard let enumerator = fm.enumerator(at: directory, includingPropertiesForKeys: nil) else { return [] }
    return enumerator.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    print("사용 방법 - Detectliterals <Swift 프로젝트 경로> [출력 파일 경로]")
    exit(1)
}

let inputPath = args[1]
let outputPath = args.count >= 3 ? args[2] : "extracted_literals.json"

let root = URL(fileURLWithPath: inputPath)
let outputURL = URL(fileURLWithPath: outputPath)

var allLiterals: [LiteralEntry] = []

for file in collectSwiftFiles(in: root) {
    do {
        let fileContent = try String(contentsOf: file)
        let syntax = Parser.parse(source: fileContent)
        let extractor = LiteralExtractor(viewMode: .sourceAccurate)
        extractor.currentFile = file.path
        extractor.sourceLines = fileContent.components(separatedBy: .newlines)
        extractor.walk(syntax)
        allLiterals.append(contentsOf: extractor.literals)
    } catch {
        print("파싱 실패: \(file.lastPathComponent) – \(error)")
    }
}

do {
    let jsonData = try JSONEncoder().encode(allLiterals)
    try jsonData.write(to: outputURL)
    print("JSON : \(outputURL.path)")
} catch {
    print(" Error \(error)")
}

