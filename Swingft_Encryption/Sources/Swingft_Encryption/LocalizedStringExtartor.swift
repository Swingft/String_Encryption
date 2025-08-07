import Foundation
import SwiftSyntax

final class LocalizedStringExtractor: SyntaxVisitor {
    private(set) var excludedStrings: [(String, String)] = []
    private let filePath: String
    private var insideLocalizedKeyContext = false

    init(filePath: String) {
        self.filePath = filePath
        super.init(viewMode: .sourceAccurate)
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        if let firstArg = node.argumentList.first,
           firstArg.label == nil,
           let strExpr = firstArg.expression.as(StringLiteralExprSyntax.self),
           node.trailingClosure != nil {
            add(strExpr)
        }
        return .visitChildren
    }

    override func visit(_ node: VariableDeclSyntax) -> SyntaxVisitorContinueKind {
        for binding in node.bindings {
            if let type = binding.typeAnnotation?.type.trimmedDescription,
               type == "LocalizedStringKey" {

                if let accessor = binding.accessor {
                    insideLocalizedKeyContext = true
                    walk(accessor)
                    insideLocalizedKeyContext = false
                }

                if let initializer = binding.initializer?.value.as(StringLiteralExprSyntax.self) {
                    add(initializer)
                }
            }
        }
        return .skipChildren
    }

    override func visit(_ node: FunctionDeclSyntax) -> SyntaxVisitorContinueKind {
        if node.signature.returnClause?.type.trimmedDescription == "LocalizedStringKey" {
            insideLocalizedKeyContext = true
        }
        return .visitChildren
    }

    override func visitPost(_ node: FunctionDeclSyntax) {
        insideLocalizedKeyContext = false
    }


    override func visit(_ node: StringLiteralExprSyntax) -> SyntaxVisitorContinueKind {
        guard insideLocalizedKeyContext else { return .skipChildren }
        add(node)
        return .skipChildren
    }

    private func add(_ strExpr: StringLiteralExprSyntax) {
        let value = strExpr.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
        excludedStrings.append((filePath, "\"\(value)\""))
    }
}

