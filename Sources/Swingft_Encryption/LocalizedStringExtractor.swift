import Foundation
import SwiftSyntax


final class LocalizedStringExtractor: SyntaxVisitor {
    private(set) var localizedStrings: [(String, String)] = []  
    private let filePath: String

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        guard isLocalizedCall(node) else { return .visitChildren }

        for arg in node.arguments {
            collectStrings(from: arg.expression)
        }
        return .visitChildren
    }

   
    private func isLocalizedCall(_ node: FunctionCallExprSyntax) -> Bool {
        if let callee = node.calledExpression.as(DeclReferenceExprSyntax.self) {
            if callee.baseName.text == "NSLocalizedString" { return true }
            if callee.baseName.text == "String",
               node.arguments.contains(where: { $0.label?.text == "localized" }) {
                return true
            }
        }
        if let member = node.calledExpression.as(MemberAccessExprSyntax.self) {
            if member.declName.baseName.text == "localized" { return true }
        }
        return false
    }

    private func collectStrings(from expr: ExprSyntax) {
        if let lit = expr.as(StringLiteralExprSyntax.self) {
            add(literal: lit)
            return
        }

        if let call = expr.as(FunctionCallExprSyntax.self) {
            for a in call.arguments { collectStrings(from: a.expression) }
            return
        }
        if let tuple = expr.as(TupleExprSyntax.self) {
            for el in tuple.elements { collectStrings(from: el.expression) }
            return
        }
        if let array = expr.as(ArrayExprSyntax.self) {
            for el in array.elements { collectStrings(from: el.expression) }
            return
        }
        if let dict = expr.as(DictionaryExprSyntax.self),
           let list = dict.content.as(DictionaryElementListSyntax.self) {
            for el in list { collectStrings(from: el.key); collectStrings(from: el.value) }
            return
        }
    }

    private func add(literal: StringLiteralExprSyntax) {
        let raw = literal.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let ln = SourceLoc.line(of: literal, filePath: filePath)
        localizedStrings.append(("\(filePath):\(ln)", raw))
    }
}
