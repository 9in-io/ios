import CryptoKit
import Foundation
import Security
@testable import Nine

/// A signing key for tests: its public JWK and a function that signs.
struct TestKey: @unchecked Sendable {
    let alg: String
    let kid: String
    let jwk: [String: JSONValue]
    let sign: @Sendable (Data) -> Data

    /// The JWK with a different (or no) `alg` member.
    func jwk(alg value: String?) -> [String: JSONValue] {
        var copy = jwk
        copy["alg"] = value.map(JSONValue.string)
        return copy
    }
}

/// A SecKey in a box, so it can live in a static.
private struct KeyBox: @unchecked Sendable {
    let key: SecKey
}

enum TestKeys {
    static let allAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]

    private static let rsa2048 = KeyBox(key: rsaKey(bits: 2048))
    private static let rsa2048b = KeyBox(key: rsaKey(bits: 2048))
    private static let rsa1024 = KeyBox(key: rsaKey(bits: 1024))

    private static func rsaKey(bits: Int) -> SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: bits]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("RSA key generation failed: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }

    /// A new key for `alg` (RSA keys are generated once per run and shared).
    static func make(_ alg: String, kid: String? = nil, weakRSA: Bool = false, otherRSA: Bool = false) -> TestKey {
        let kid = kid ?? "k_\(alg.lowercased())_\(UUID().uuidString.prefix(8))"
        switch alg {
        case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
            let privateKey = (weakRSA ? rsa1024 : otherRSA ? rsa2048b : rsa2048).key
            let (n, e) = rsaComponents(SecKeyCopyPublicKey(privateKey)!)
            let algorithm: SecKeyAlgorithm = [
                "RS256": .rsaSignatureMessagePKCS1v15SHA256, "RS384": .rsaSignatureMessagePKCS1v15SHA384, "RS512": .rsaSignatureMessagePKCS1v15SHA512,
                "PS256": .rsaSignatureMessagePSSSHA256, "PS384": .rsaSignatureMessagePSSSHA384, "PS512": .rsaSignatureMessagePSSSHA512,
            ][alg]!
            let box = KeyBox(key: privateKey)
            return TestKey(alg: alg, kid: kid, jwk: ["kty": "RSA", "kid": .string(kid), "alg": .string(alg), "use": "sig", "n": .string(Base64URL.encode(n)), "e": .string(Base64URL.encode(e))]) { data in
                var error: Unmanaged<CFError>?
                return SecKeyCreateSignature(box.key, algorithm, data as CFData, &error)! as Data
            }
        case "ES256":
            let key = P256.Signing.PrivateKey()
            let raw = key.publicKey.rawRepresentation
            return TestKey(alg: alg, kid: kid, jwk: ["kty": "EC", "crv": "P-256", "kid": .string(kid), "alg": "ES256", "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32)))]) { data in
                try! key.signature(for: data).rawRepresentation
            }
        case "ES384":
            let key = P384.Signing.PrivateKey()
            let raw = key.publicKey.rawRepresentation
            return TestKey(alg: alg, kid: kid, jwk: ["kty": "EC", "crv": "P-384", "kid": .string(kid), "alg": "ES384", "x": .string(Base64URL.encode(raw.prefix(48))), "y": .string(Base64URL.encode(raw.suffix(48)))]) { data in
                try! key.signature(for: data).rawRepresentation
            }
        case "EdDSA":
            let key = Curve25519.Signing.PrivateKey()
            return TestKey(alg: alg, kid: kid, jwk: ["kty": "OKP", "crv": "Ed25519", "kid": .string(kid), "alg": "EdDSA", "x": .string(Base64URL.encode(key.publicKey.rawRepresentation))]) { data in
                try! key.signature(for: data)
            }
        default:
            fatalError("no test key for \(alg)")
        }
    }

    /// Modulus and exponent of an RSA public key (PKCS #1 DER from Security).
    private static func rsaComponents(_ publicKey: SecKey) -> (Data, Data) {
        let der = [UInt8](SecKeyCopyExternalRepresentation(publicKey, nil)! as Data)
        var index = 0
        func readLength() -> Int {
            let first = der[index]; index += 1
            if first & 0x80 == 0 { return Int(first) }
            var length = 0
            for _ in 0..<Int(first & 0x7F) { length = length << 8 | Int(der[index]); index += 1 }
            return length
        }
        precondition(der[index] == 0x30); index += 1; _ = readLength()
        precondition(der[index] == 0x02); index += 1
        let nLength = readLength(); let n = Data(der[index..<index + nLength]); index += nLength
        precondition(der[index] == 0x02); index += 1
        let eLength = readLength(); let e = Data(der[index..<index + eLength])
        return (n, e)
    }
}

enum TestJWT {
    static func encode(_ object: [String: JSONValue]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return Base64URL.encode(try! encoder.encode(object))
    }

    /// A signed compact JWS. `header` members replace the defaults (`alg`, `kid`, `typ: JWT`).
    static func sign(_ claims: [String: JSONValue], key: TestKey, header: [String: JSONValue] = [:]) -> String {
        var fullHeader: [String: JSONValue] = ["alg": .string(key.alg), "kid": .string(key.kid), "typ": "JWT"]
        for (name, value) in header { fullHeader[name] = value }
        let input = "\(encode(fullHeader)).\(encode(claims))"
        return "\(input).\(Base64URL.encode(key.sign(Data(input.utf8))))"
    }

    /// An unsigned token (`alg: none`).
    static func unsigned(_ claims: [String: JSONValue], header: [String: JSONValue] = ["alg": "none", "typ": "JWT"]) -> String {
        "\(encode(header)).\(encode(claims))."
    }
}
