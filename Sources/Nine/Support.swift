import CryptoKit
import Foundation
import Security

// Small helpers shared by the rest of the package.

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict base64url (no padding, no other characters). Nil when the input isn't base64url.
    static func decode(_ string: String) -> Data? {
        for scalar in string.unicodeScalars {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_": continue
            default: return nil
            }
        }
        var base64 = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        switch base64.count % 4 {
        case 1: return nil
        case 2: base64 += "=="
        case 3: base64 += "="
        default: break
        }
        return Data(base64Encoded: base64)
    }
}

enum Random {
    /// `count` bytes from the system's cryptographically secure generator.
    static func bytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        if SecRandomCopyBytes(kSecRandomDefault, count, &bytes) != errSecSuccess {
            // SystemRandomNumberGenerator is also cryptographically secure on Apple platforms.
            var generator = SystemRandomNumberGenerator()
            for index in bytes.indices { bytes[index] = generator.next() }
        }
        return Data(bytes)
    }

    /// A base64url string of `count` random bytes.
    static func string(_ count: Int = 32) -> String {
        Base64URL.encode(bytes(count))
    }
}

/// Proof Key for Code Exchange (RFC 7636), S256 only.
enum PKCE {
    /// A new code verifier: 64 base64url characters (48 random bytes), within RFC 7636's 43–128.
    static func makeVerifier() -> String {
        Random.string(48)
    }

    /// `BASE64URL(SHA256(ASCII(code_verifier)))`.
    static func challenge(for verifier: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8))))
    }
}

/// Compares two strings without returning early on the first difference.
func constantTimeEquals(_ a: String, _ b: String) -> Bool {
    let x = Array(a.utf8)
    let y = Array(b.utf8)
    guard x.count == y.count else { return false }
    var difference: UInt8 = 0
    for index in x.indices { difference |= x[index] ^ y[index] }
    return difference == 0
}

/// A value behind a lock, for the few places where state is read synchronously from any thread.
final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) { self.value = value }

    func withLock<T>(_ body: (inout Value) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }

    var current: Value { withLock { $0 } }
}

enum FormEncoding {
    private static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    static func escape(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
    }

    /// `application/x-www-form-urlencoded`, every reserved character percent-encoded.
    static func encode(_ fields: [(String, String)]) -> Data {
        Data(fields.map { "\(escape($0.0))=\(escape($0.1))" }.joined(separator: "&").utf8)
    }

    static func decode(_ body: Data) -> [String: String] {
        var fields: [String: String] = [:]
        for pair in String(decoding: body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = String(parts[0]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(parts[0])
            let value = parts.count > 1 ? (String(parts[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(parts[1])) : ""
            fields[key] = value
        }
        return fields
    }
}

/// Issuer URLs: https only (plain http for localhost and loopback, or when allowed), no query,
/// fragment or credentials, one trailing slash dropped. The same rules as every 9in SDK.
enum Issuer {
    static func normalize(_ issuer: String, allowInsecure: Bool) throws -> String {
        guard let components = URLComponents(string: issuer),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty
        else {
            throw NineError(.invalidIssuer, "not a URL: \(issuer)")
        }
        if components.query != nil || components.fragment != nil || components.user != nil || components.password != nil {
            throw NineError(.invalidIssuer, "an issuer has no query, fragment or credentials")
        }
        guard scheme == "https" || (scheme == "http" && (allowInsecure || isLocal(host))) else {
            throw NineError(.insecureIssuer, "issuer must use https (got \(scheme)://\(host)); plain http is only accepted for localhost")
        }
        return issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
    }

    /// Whether an endpoint URL from discovery may be called: https, or http under the issuer rules.
    static func isSecureEndpoint(_ url: URL, allowInsecure: Bool) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host, !host.isEmpty else { return false }
        return scheme == "https" || (scheme == "http" && (allowInsecure || isLocal(host)))
    }

    static func isLocal(_ hostname: String) -> Bool {
        var host = hostname.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if host == "localhost" || host.hasSuffix(".localhost") || host == "::1" { return true }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts[0] == "127" && parts.allSatisfy { part in
            (1...3).contains(part.count) && part.allSatisfy(\.isASCII) && part.allSatisfy(\.isNumber)
        }
    }

    /// Two issuer strings name the same issuer (a trailing slash doesn't count).
    static func same(_ a: String, _ b: String) -> Bool {
        let trim = { (s: String) in s.hasSuffix("/") ? String(s.dropLast()) : s }
        return trim(a) == trim(b)
    }
}
