import Foundation
import SwiftSyntax

struct SwingftConfig: Decodable {
    struct Options: Decodable {
        let Encryption_strings: Bool
    }

    struct Exclude: Decodable {
        let encryption: [String]
    }

    let options: Options
    let exclude: Exclude
}

final class ConfigLoader {
    static func loadConfig(from path: String) -> ParsedConfig? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let config = try? JSONDecoder().decode(SwingftConfig.self, from: data) else {
            return nil
        }

        return ParsedConfig(
            shouldEncryptStrings: config.options.Encryption_strings,
            encryptionExcludes: config.exclude.encryption
        )
    }

    static func extractExcludedStrings(from source: String, filePath: String, excludedList: [String]) -> [(String, String)] {
        var result: [(String, String)] = []
        let lines = source.components(separatedBy: .newlines)

        for (idx, line) in lines.enumerated() {
            for keyword in excludedList where line.contains(keyword) {
                let ln = idx + 1
                result.append(("\(filePath):\(ln)", "\"\(keyword)\""))
            }
        }
        return result
    }

}

struct ParsedConfig {
    let shouldEncryptStrings: Bool
    let encryptionExcludes: [String]
}

