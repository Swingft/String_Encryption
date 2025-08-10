import SwiftSyntax
import SwiftParser

final class LocalizedStringResourceExtractor: SyntaxVisitor {
    private let filePath: String
    private let source: String
    private(set) var resources: [(String, String)] = []

    private lazy var converter: SourceLocationConverter = {
        SourceLocationConverter(fileName: filePath, tree: Parser.parse(source: source))
    }()

    init(filePath: String, source: String) {
        self.filePath = filePath
        self.source = source
        super.init(viewMode: .sourceAccurate)
    }

    private func line(of node: some SyntaxProtocol) -> Int {
        let pos = node.positionAfterSkippingLeadingTrivia
        let loc = converter.location(for: pos)
        return loc.line  
    }

    override func visit(_ node: VariableDeclSyntax) -> SyntaxVisitorContinueKind {
        for binding in node.bindings {
            guard
                let typeAnnotation = binding.typeAnnotation?.type.trimmedDescription,
                typeAnnotation == "LocalizedStringResource",
                let initializer = binding.initializer,
                let str = initializer.value.as(StringLiteralExprSyntax.self)
            else { continue }

            let value = str.segments.description.trimmingCharacters(in: .whitespacesAndNewlines)
            let ln = line(of: str) 
            resources.append(("\(filePath):\(ln)", "\"\(value)\""))
        }
        return .skipChildren
    }
}
