import Foundation
import SwiftSyntax

final class DebugStringExtractor: SyntaxVisitor {
    private(set) var debugStrings: [(String, String)] = []
    private let filePath: String
    private let debugFunctions: Set<String> = [
        "print", "NSLog", "debugPrint", "assert", "fatalError"
    ]

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        if let callee = node.calledExpression.as(DeclReferenceExprSyntax.self) {
            let name = callee.baseName.text
            if debugFunctions.contains(name) {
                for arg in node.arguments {
                    if let str = arg.expression.as(StringLiteralExprSyntax.self) {
                        let raw = str.description.trimmingCharacters(in: .whitespacesAndNewlines)
                        debugStrings.append((filePath, raw))
                    }
                }
            }
        }
        return .visitChildren
    }
}
