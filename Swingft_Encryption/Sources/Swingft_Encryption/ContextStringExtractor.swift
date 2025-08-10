import SwiftSyntax

final class ContextStringExtractor: SyntaxVisitor {
    private(set) var excludedStrings: [(String, String)] = []
    private let filePath: String

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        if node.calledExpression.is(MemberAccessExprSyntax.self) {
            for arg in node.arguments {
                if let str = arg.expression.as(StringLiteralExprSyntax.self) {
                    add(str)
                }
            }
        }
        return .visitChildren
    }

    override func visit(_ node: LabeledExprSyntax) -> SyntaxVisitorContinueKind {
        if node.label != nil,
           let str = node.expression.as(StringLiteralExprSyntax.self) {
            add(str)
        }
        return .visitChildren
    }

    private func add(_ str: StringLiteralExprSyntax) {
        let raw = str.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let ln = SourceLoc.line(of: str, filePath: filePath)

        excludedStrings.append(("\(filePath):\(ln)", raw))

    }
}
