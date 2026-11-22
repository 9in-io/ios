import CryptoKit
import Foundation
import Security

/// A compact JWS, decoded but not verified.
struct JWT: Sendable {
    let header: [String: JSONValue]
    let claims: [String: JSONValue]
    /// `base64url(header).base64url(payload)` as ASCII: what the signature covers.
    let signingInput: Data
    let signature: Data

    init?(_ token: String) {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Base64URL.decode(String(parts[0])),
              let payloadData = Base64URL.decode(String(parts[1])),
              let signature = Base64URL.decode(String(parts[2])),
              let header = JSON.object(headerData),
              let claims = JSON.object(payloadData)
        else { return nil }
        self.header = header
        self.claims = claims
        self.signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        self.signature = signature
    }

    /// The claims of a token whose signature was checked before it was stored.
    static func claims(of token: String) -> [String: JSONValue]? {
        JWT(token)?.claims
    }
}

/// A public key from the tenant's JWKS.
struct JWK: Decodable, Sendable, Equatable {
    var kty: String
    var kid: String?
    var alg: String?
    var use: String?
    var n: String?
    var e: String?
    var crv: String?
    var x: String?
    var y: String?
}

/// JWS signature checks for every asymmetric algorithm of 9in's key library: RS256/384/512 and
/// PS256/384/512 through Security (`SecKey`), ES256/ES384 and EdDSA (Ed25519) through CryptoKit.
/// The key decides the algorithm: a token naming another algorithm than its key is refused.
enum JWS {
    /// The algorithms 9in signs ID tokens with (HMAC keys never sign ID tokens).
    static let algorithms: Set<String> = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"]

    enum Failure: Error, Equatable {
        case unsupportedAlgorithm
        case algorithmMismatch
        case wrongKeyType
        case weakKey
        case badKey
        case badSignature
    }

    /// Checks `signature` over `input` with `jwk` for `alg`; throws `Failure` when it doesn't hold.
    static func verify(alg: String, jwk: JWK, input: Data, signature: Data) throws {
        guard algorithms.contains(alg) else { throw Failure.unsupportedAlgorithm }
        if let keyAlg = jwk.alg, keyAlg != alg { throw Failure.algorithmMismatch }
        if let use = jwk.use, use != "sig" { throw Failure.wrongKeyType }
        let valid: Bool
        switch alg {
        case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
            valid = try verifyRSA(alg: alg, jwk: jwk, input: input, signature: signature)
        case "ES256":
            guard jwk.kty == "EC", jwk.crv == "P-256" else { throw Failure.wrongKeyType }
            guard let x = jwk.x.flatMap(Base64URL.decode), let y = jwk.y.flatMap(Base64URL.decode), x.count == 32, y.count == 32,
                  let key = try? P256.Signing.PublicKey(rawRepresentation: x + y)
            else { throw Failure.badKey }
            guard signature.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { throw Failure.badSignature }
            valid = key.isValidSignature(sig, for: input)
        case "ES384":
            guard jwk.kty == "EC", jwk.crv == "P-384" else { throw Failure.wrongKeyType }
            guard let x = jwk.x.flatMap(Base64URL.decode), let y = jwk.y.flatMap(Base64URL.decode), x.count == 48, y.count == 48,
                  let key = try? P384.Signing.PublicKey(rawRepresentation: x + y)
            else { throw Failure.badKey }
            guard signature.count == 96, let sig = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else { throw Failure.badSignature }
            valid = key.isValidSignature(sig, for: input)
        case "EdDSA":
            guard jwk.kty == "OKP", jwk.crv == "Ed25519" else { throw Failure.wrongKeyType }
            guard let x = jwk.x.flatMap(Base64URL.decode), x.count == 32,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: x)
            else { throw Failure.badKey }
            guard signature.count == 64 else { throw Failure.badSignature }
            valid = key.isValidSignature(signature, for: input)
        default:
            throw Failure.unsupportedAlgorithm
        }
        if !valid { throw Failure.badSignature }
    }

    private static func verifyRSA(alg: String, jwk: JWK, input: Data, signature: Data) throws -> Bool {
        guard jwk.kty == "RSA" else { throw Failure.wrongKeyType }
        guard let n = jwk.n.flatMap(Base64URL.decode), let e = jwk.e.flatMap(Base64URL.decode), !n.isEmpty, !e.isEmpty else { throw Failure.badKey }
        guard bitLength(n) >= 2048 else { throw Failure.weakKey }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(DER.rsaPublicKey(modulus: n, exponent: e) as CFData, attributes as CFDictionary, nil) else {
            throw Failure.badKey
        }
        let algorithm: SecKeyAlgorithm
        switch alg {
        case "RS256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case "RS384": algorithm = .rsaSignatureMessagePKCS1v15SHA384
        case "RS512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
        // Security's PSS uses MGF1 with the same hash and a salt as long as the hash, as JWA requires.
        case "PS256": algorithm = .rsaSignatureMessagePSSSHA256
        case "PS384": algorithm = .rsaSignatureMessagePSSSHA384
        default: algorithm = .rsaSignatureMessagePSSSHA512
        }
        return SecKeyVerifySignature(key, algorithm, input as CFData, signature as CFData, nil)
    }

    /// Bits in a big-endian unsigned integer, leading zero bytes ignored.
    static func bitLength(_ bytes: Data) -> Int {
        guard let first = bytes.firstIndex(where: { $0 != 0 }) else { return 0 }
        return (bytes.endIndex - first - 1) * 8 + (8 - bytes[first].leadingZeroBitCount)
    }

    /// The hash OpenID Connect uses for `at_hash` with `alg` (SHA-512 for Ed25519, like 9in).
    static func atHash(_ accessToken: String, alg: String) -> String {
        let data = Data(accessToken.utf8)
        let digest: Data
        if alg == "EdDSA" || alg.hasSuffix("512") {
            digest = Data(SHA512.hash(data: data))
        } else if alg.hasSuffix("384") {
            digest = Data(SHA384.hash(data: data))
        } else {
            digest = Data(SHA256.hash(data: data))
        }
        return Base64URL.encode(digest.prefix(digest.count / 2))
    }
}

/// Just enough DER to hand an RSA public key (PKCS #1 `RSAPublicKey`) to `SecKeyCreateWithData`.
enum DER {
    static func rsaPublicKey(modulus: Data, exponent: Data) -> Data {
        sequence(integer(modulus) + integer(exponent))
    }

    static func integer(_ value: Data) -> [UInt8] {
        var bytes = [UInt8](value)
        while bytes.count > 1, bytes[0] == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        return [0x02] + length(bytes.count) + bytes
    }

    static func sequence(_ content: [UInt8]) -> Data {
        Data([0x30] + length(content.count) + content)
    }

    static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
