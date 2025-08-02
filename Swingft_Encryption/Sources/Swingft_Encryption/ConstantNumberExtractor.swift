import SwiftSyntax

final class ConstantNumberExtractor: SyntaxVisitor {
    private(set) var constants: [(String, String)] = []
    private let filePath: String
    private var scopeDepth: Int = 0
    private let allowedTypes: Set<String> = ["Int", "Double", "Float"]

    init(viewMode: SyntaxTreeViewMode = .sourceAccurate, filePath: String) {
        self.filePath = filePath
        super.init(viewMode: viewMode)
    }

    override func visit(_ node: CodeBlockSyntax) -> SyntaxVisitorContinueKind {
        scopeDepth += 1
        return .visitChildren
    }
    override func visitPost(_ node: CodeBlockSyntax) {
        scopeDepth -= 1
    }

    override func visit(_ node: StructDeclSyntax) -> SyntaxVisitorContinueKind {
        scopeDepth += 1
        return .visitChildren
    }
    override func visitPost(_ node: StructDeclSyntax) {
        scopeDepth -= 1
    }

    override func visit(_ node: ClassDeclSyntax) -> SyntaxVisitorContinueKind {
        scopeDepth += 1
        return .visitChildren
    }
    override func visitPost(_ node: ClassDeclSyntax) {
        scopeDepth -= 1
    }

    override func visit(_ node: EnumDeclSyntax) -> SyntaxVisitorContinueKind {
        scopeDepth += 1
        return .visitChildren
    }
    override func visitPost(_ node: EnumDeclSyntax) {
        scopeDepth -= 1
    }

    override func visit(_ node: FunctionDeclSyntax) -> SyntaxVisitorContinueKind {
        scopeDepth += 1
        return .visitChildren
    }
    override func visitPost(_ node: FunctionDeclSyntax) {
        scopeDepth -= 1
    }

    override func visit(_ node: VariableDeclSyntax) -> SyntaxVisitorContinueKind {
        guard scopeDepth > 0 else { return .skipChildren }

        for binding in node.bindings {
            guard let initializer = binding.initializer else { continue }

            let pattern = binding.pattern.trimmedDescription
            let typeAnnotation = binding.typeAnnotation?.type.trimmedDescription

            //  타입이 명시되지 않은 변수는 무시
            guard let type = typeAnnotation, allowedTypes.contains(type) else { continue }

            if let literal = findNumberLiteral(from: initializer.value) {
                let declaration = "\(pattern): \(type) = \(literal.value)"
                constants.append(("NUM: \(filePath)", declaration))
            }
        }

        return .skipChildren
    }

    private func findNumberLiteral(from expr: ExprSyntax) -> (kind: Kind, value: String)? {
        if let float = expr.as(FloatLiteralExprSyntax.self) {
            return (.float, float.floatingDigits.text)
        }
        if let int = expr.as(IntegerLiteralExprSyntax.self) {
            return (.int, int.digits.text)
        }
        if let sequence = expr.as(SequenceExprSyntax.self) {
            for element in sequence.elements {
                if let found = findNumberLiteral(from: element) {
                    return found
                }
            }
        }
        return nil
    }

    enum Kind {
        case int, float
    }
}

