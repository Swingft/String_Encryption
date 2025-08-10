import Foundation
import SwiftSyntax


final class LocalizedStringExtractor: SyntaxVisitor {
    private(set) var excludedStrings: [(String, String)] = []
    private let filePath: String

    init(filePath: String) {
        self.filePath = filePath
        super.init(viewMode: .sourceAccurate)
    }

    override func visit(_ node: ReturnStmtSyntax) -> SyntaxVisitorContinueKind {
        if let lit = unwrapStringLiteral(from: node.expression) {
            add(lit)
            collectNestedLiterals(lit)
        }
        return .visitChildren
    }

    override func visit(_ node: StringLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        if isInSwitchCaseLine(node) {
            add(node)
            collectNestedLiterals(node)
        } else if containsInterpolation(node) {
            add(node)
            collectNestedLiterals(node)
        }
        return .skipChildren
    }

    private func unwrapStringLiteral(from expr: ExprSyntax?) -> StringLiteralExprSyntax? {
        guard let expr else { return nil }
        if let lit = expr.as(StringLiteralExprSyntax.self) { return lit }
        if let tuple = expr.as(TupleExprSyntax.self),
           tuple.elements.count == 1,
           let only = tuple.elements.first,
           let inner = only.expression.as(StringLiteralExprSyntax.self) {
            return inner
        }
        return nil
    }

    private func isInSwitchCaseLine(_ str: StringLiteralExprSyntax) -> Bool {
        guard let firstTok = str.firstToken(viewMode: .sourceAccurate) else { return false }

        var tokOpt = firstTok.previousToken(viewMode: .sourceAccurate)
        var steps = 0

        while let tok = tokOpt, steps < 100 {
            if triviaHasNewline(tok.trailingTrivia) || triviaHasNewline(firstTok.leadingTrivia) {
                break
            }

            let text = tok.text
            if text == "case" || text == "default" {
                return true
            }

            tokOpt = tok.previousToken(viewMode: .sourceAccurate)
            steps += 1
        }
        return false
    }

    private func triviaHasNewline(_ trivia: Trivia) -> Bool {
        if trivia.description.contains("\n") || trivia.description.contains("\r") { return true }
        for piece in trivia {
            if String(describing: piece).contains("newlines") { return true }
        }
        return false
    }

    private func containsInterpolation(_ str: StringLiteralExprSyntax) -> Bool {
        if str.segments.contains(where: { $0.as(ExpressionSegmentSyntax.self) != nil }) {
            return true
        }
        return str.description.contains("\\(")
    }


    private func collectNestedLiterals(_ str: StringLiteralExprSyntax) {
        var sawExprSegment = false

        for seg in str.segments {
            if let exprSeg = seg.as(ExpressionSegmentSyntax.self) {
                sawExprSegment = true
                let v = InnerStringCollector(filePath: filePath)
                v.walk(exprSeg) // exprSeg.expression 이 없는 버전 대비: 세그먼트 자체를 걷기
                excludedStrings.append(contentsOf: v.collected)
            }
        }

        if !sawExprSegment && str.description.contains("\\(") {
            let text = str.description as NSString
            let outerPattern = #"\\\((?:[^"\\]|\\.|"([^"\\]|\\.)*")*\)"#
            let innerPattern = #""((?:[^"\\]|\\.)*)""#

            guard
                let outer = try? NSRegularExpression(pattern: outerPattern),
                let inner = try? NSRegularExpression(pattern: innerPattern)
            else { return }

            for m in outer.matches(in: str.description, range: NSRange(location: 0, length: text.length)) {
                let outerStr = text.substring(with: m.range) as NSString
                let len = outerStr.length
                for s in inner.matches(in: outerStr as String, range: NSRange(location: 0, length: len)) {
                    let captured = outerStr.substring(with: s.range(at: 1))
                    excludedStrings.append((filePath, "\"\(captured)\""))
                }
            }
        }
    }

    private func add(_ str: StringLiteralExprSyntax) {
        let value = str.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let ln = SourceLoc.line(of: str, filePath: filePath)

        excludedStrings.append(("\(filePath):\(ln)", "\"\(value)\""))
    }
}

private final class InnerStringCollector: SyntaxVisitor {
    private let filePath: String
    var collected: [(String, String)] = []

    init(filePath: String) {
        self.filePath = filePath
        super.init(viewMode: .sourceAccurate)
    }

    override func visit(_ node: StringLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        let value = node.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let ln = SourceLoc.line(of: node, filePath: filePath)

        collected.append(("\(filePath):\(ln)", "\"\(value)\""))
        return .skipChildren
    }
}

