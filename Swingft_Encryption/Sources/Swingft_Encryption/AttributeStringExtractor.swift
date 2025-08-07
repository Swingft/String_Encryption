import Foundation

struct AttributeStringExtractor {
    static func extract(from source: String) -> [(String, Int)] {
        let pattern = #"@[\w_]+\s*\((?:[^\"]*\"([^\"]+)\"[^\)]*)\)"#
        var results: [(String, Int)] = []

        let lines = source.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                let matches = regex.matches(in: line, range: NSRange(location: 0, length: line.utf16.count))
                for match in matches {
                    if match.numberOfRanges >= 2,
                       let range = Range(match.range(at: 1), in: line) {
                        let extracted = String(line[range])
                        results.append((extracted, index + 1))
                    }
                }
            }
        }

        return results
    }
}
