import SwiftSyntax

enum SourceLoc {
    static func line(of node: some SyntaxProtocol, filePath: String) -> Int {
        let converter = SourceLocationConverter(fileName: filePath, tree: node.root)
        if let lit = node.as(StringLiteralExprSyntax.self),
           let firstTok = lit.firstToken(viewMode: .sourceAccurate) {
            let pos = firstTok.positionAfterSkippingLeadingTrivia
            return converter.location(for: pos).line
        }
        #if swift(<5.10)
        return node.startLocation(converter: converter).line ?? 0
        #else
        return node.startLocation(converter: converter).line
        #endif
    }
}
