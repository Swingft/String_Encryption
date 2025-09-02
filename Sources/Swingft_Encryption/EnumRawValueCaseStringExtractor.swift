import Foundation
import SwiftSyntax

final class EnumRawValueCaseStringExtractor: SyntaxVisitor {
    private let filePath: String
    private var enumStack: [Bool] = []  
    private(set) var enumCaseStrings: [(String, String)] = [] 

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }


    override func visit(_ node: EnumDeclSyntax) -> SyntaxVisitorContinueKind {
        enumStack.append(isStringRawEnum(node))
        return .visitChildren
    }

    override func visitPost(_ node: EnumDeclSyntax) {
        _ = enumStack.popLast()
    }

    override func visit(_ node: EnumCaseElementSyntax) -> SyntaxVisitorContinueKind {
        guard enumStack.last == true else { return .visitChildren }
        // case foo = "HELLO"
        if let initClause = node.rawValue,
           let lit = initClause.value.as(StringLiteralExprSyntax.self) {
            add(literal: lit)
        }
        return .visitChildren
    }

  
    private func isStringRawEnum(_ node: EnumDeclSyntax) -> Bool {
        guard let clause = node.inheritanceClause else { return false }
        for it in clause.inheritedTypes {
            
            let t = it.type.description.replacingOccurrences(of: " ", with: "")
            if t == "String" || t.hasSuffix(".String") { return true }
        }
        return false
    }

    private func add(literal: StringLiteralExprSyntax) {
        let raw = literal.description.trimmingCharacters(in: .whitespacesAndNewlines)
        let ln = SourceLoc.line(of: literal, filePath: filePath)
        enumCaseStrings.append(("\(filePath):\(ln)", raw))
    }
}
