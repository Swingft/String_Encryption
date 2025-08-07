import SwiftSyntax

final class LabeledArgumentStringExtractor: SyntaxVisitor {
    private(set) var excludedStrings: [(String, String)] = []
    private let filePath: String
    private let targetLabels: Set<String> = ["title", "subtitle", "version"]

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        for arg in node.arguments {
            if let label = arg.label?.text,
               targetLabels.contains(label),
               let strExpr = arg.expression.as(StringLiteralExprSyntax.self) {
                let value = strExpr.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
                excludedStrings.append((filePath, "\"\(value)\""))
            }
        }
        return .visitChildren
    }
}

