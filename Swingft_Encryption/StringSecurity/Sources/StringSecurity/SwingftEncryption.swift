import Foundation
import CryptoKit

@available(iOS 13.0, macOS 10.15, *)
public class SwingftEncryption {
        private static var cache: [String: String] = [:]
        private static var key: Data?
        
        public static func configure(key: Data) {
            self.key = key
        }
        
    
        public static func resolve(_ base64: String) -> String {
            if let decrypted = cache[base64] {
                return decrypted
            }
            let decrypted = decrypt(base64: base64)
            cache[base64] = decrypted
            return decrypted
        }
        
        @available(iOS 13.0, macOS 10.15, *)
        fileprivate static func decrypt(base64: String) -> String {
            guard let key else {
                assertionFailure("SwingftEncryption not configured with key")
                return ""
            }
            guard let data = Data(base64Encoded: base64) else { return "" }
            
            let nonce = data.prefix(12)
            let ciphertext = data.dropFirst(12)
            let tag = ciphertext.suffix(16)
            let encryptedBody = ciphertext.dropLast(16)
            
            do {
                let sealedBox = try ChaChaPoly.SealedBox(
                    nonce: try ChaChaPoly.Nonce(data: nonce),
                    ciphertext: encryptedBody,
                    tag: tag
                )
                let decrypted = try ChaChaPoly.open(sealedBox, using: SymmetricKey(data: key))
                return String(data: decrypted, encoding: .utf8) ?? ""
            } catch {
                return ""
            }
        }
    }
    
    
@available(iOS 13.0, macOS 10.15, *)
public final class EncryptedString: CustomStringConvertible, ExpressibleByStringLiteral {
        private let base64: String
        private lazy var decrypted: String = {
            return SwingftEncryption.decrypt(base64: base64)
        }()
        
        public init(stringLiteral value: StringLiteralType) {
            self.base64 = value
        }
        
        public init(_ base64: String) {
            self.base64 = base64
        }
        
        public var description: String {
            return decrypted
        }
        
        public func asString() -> String {
            return decrypted
        }
    }
    

