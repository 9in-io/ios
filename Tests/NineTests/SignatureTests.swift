import CryptoKit
import Foundation
import Testing
@testable import Nine

@Suite("JWS signatures for every algorithm of the key library")
struct SignatureTests {
    private func jwk(_ object: [String: JSONValue]) throws -> JWK {
        try JSONDecoder().decode(JWK.self, from: JSONEncoder().encode(object))
    }

    @Test("A valid signature verifies", arguments: TestKeys.allAlgorithms)
    func valid(alg: String) throws {
        let key = TestKeys.make(alg)
        let input = Data("header.payload".utf8)
        try JWS.verify(alg: alg, jwk: jwk(key.jwk), input: input, signature: key.sign(input))
        // The JWK's alg member is optional.
        try JWS.verify(alg: alg, jwk: jwk(key.jwk(alg: nil)), input: input, signature: key.sign(input))
    }

    @Test("A tampered input or signature fails", arguments: TestKeys.allAlgorithms)
    func tampered(alg: String) throws {
        let key = TestKeys.make(alg)
        let input = Data("header.payload".utf8)
        var signature = key.sign(input)
        #expect(throws: JWS.Failure.badSignature) { try JWS.verify(alg: alg, jwk: try jwk(key.jwk), input: Data("header.payloaD".utf8), signature: signature) }
        signature[signature.count / 2] ^= 0x01
        #expect(throws: JWS.Failure.badSignature) { try JWS.verify(alg: alg, jwk: try jwk(key.jwk), input: input, signature: signature) }
        #expect(throws: JWS.Failure.badSignature) { try JWS.verify(alg: alg, jwk: try jwk(key.jwk), input: input, signature: Data()) }
    }

    @Test("Another key of the same type fails", arguments: TestKeys.allAlgorithms)
    func otherKey(alg: String) throws {
        let signer = TestKeys.make(alg)
        let other = TestKeys.make(alg, otherRSA: true)
        let input = Data("header.payload".utf8)
        #expect(throws: JWS.Failure.badSignature) { try JWS.verify(alg: alg, jwk: try jwk(other.jwk), input: input, signature: signer.sign(input)) }
    }

    @Test("The key decides the algorithm: a token naming another one is refused")
    func algorithmMismatch() throws {
        let rs256 = TestKeys.make("RS256")
        let input = Data("x.y".utf8)
        // A PS256 signature made with an RS256 key, presented as PS256.
        let ps = TestKeys.make("PS256")
        #expect(throws: JWS.Failure.algorithmMismatch) { try JWS.verify(alg: "PS256", jwk: try jwk(rs256.jwk), input: input, signature: ps.sign(input)) }
        #expect(throws: JWS.Failure.algorithmMismatch) { try JWS.verify(alg: "RS384", jwk: try jwk(rs256.jwk), input: input, signature: rs256.sign(input)) }
        let es256 = TestKeys.make("ES256")
        #expect(throws: JWS.Failure.algorithmMismatch) { try JWS.verify(alg: "ES384", jwk: try jwk(es256.jwk), input: input, signature: es256.sign(input)) }
    }

    @Test("The key type must fit the algorithm")
    func wrongKeyType() throws {
        let input = Data("x.y".utf8)
        let rsa = TestKeys.make("RS256")
        let ec = TestKeys.make("ES256")
        let ed = TestKeys.make("EdDSA")
        let es384 = TestKeys.make("ES384")
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "ES256", jwk: try jwk(rsa.jwk(alg: nil)), input: input, signature: ec.sign(input)) }
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "RS256", jwk: try jwk(ec.jwk(alg: nil)), input: input, signature: rsa.sign(input)) }
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "EdDSA", jwk: try jwk(ec.jwk(alg: nil)), input: input, signature: ed.sign(input)) }
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "ES256", jwk: try jwk(es384.jwk(alg: nil)), input: input, signature: ec.sign(input)) }
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "ES256", jwk: try jwk(ed.jwk(alg: nil)), input: input, signature: ec.sign(input)) }
        var encryptionKey = rsa.jwk
        encryptionKey["use"] = "enc"
        #expect(throws: JWS.Failure.wrongKeyType) { try JWS.verify(alg: "RS256", jwk: try jwk(encryptionKey), input: input, signature: rsa.sign(input)) }
    }

    @Test("alg none, HMAC and unknown algorithms are refused", arguments: ["none", "HS256", "HS384", "HS512", "RS1", "ES512", ""])
    func unsupported(alg: String) throws {
        let key = TestKeys.make("RS256")
        let input = Data("x.y".utf8)
        #expect(throws: JWS.Failure.unsupportedAlgorithm) { try JWS.verify(alg: alg, jwk: try jwk(key.jwk(alg: nil)), input: input, signature: key.sign(input)) }
    }

    @Test("RSA keys under 2048 bits are refused")
    func weakRSA() throws {
        let key = TestKeys.make("RS256", weakRSA: true)
        let input = Data("x.y".utf8)
        #expect(throws: JWS.Failure.weakKey) { try JWS.verify(alg: "RS256", jwk: try jwk(key.jwk), input: input, signature: key.sign(input)) }
    }

    @Test("Unreadable key material is refused")
    func badKeys() throws {
        let input = Data("x.y".utf8)
        let ec = TestKeys.make("ES256")
        var short = ec.jwk
        short["x"] = .string(Base64URL.encode(Data(repeating: 1, count: 31)))
        #expect(throws: JWS.Failure.badKey) { try JWS.verify(alg: "ES256", jwk: try jwk(short), input: input, signature: ec.sign(input)) }
        var offCurve = ec.jwk
        offCurve["y"] = .string(Base64URL.encode(Data(repeating: 7, count: 32)))
        // CryptoKit may accept the point and then fail the signature: refused either way.
        #expect(throws: JWS.Failure.self) { try JWS.verify(alg: "ES256", jwk: try jwk(offCurve), input: input, signature: ec.sign(input)) }
        let rsa = TestKeys.make("RS256")
        var noModulus = rsa.jwk
        noModulus["n"] = nil
        #expect(throws: JWS.Failure.badKey) { try JWS.verify(alg: "RS256", jwk: try jwk(noModulus), input: input, signature: rsa.sign(input)) }
    }

    @Test("at_hash uses the signing algorithm's hash, SHA-512 for EdDSA")
    func atHash() {
        let token = "at_example"
        func expected(_ digest: some Sequence<UInt8>) -> String {
            let bytes = Array(digest)
            return Base64URL.encode(Data(bytes.prefix(bytes.count / 2)))
        }
        #expect(JWS.atHash(token, alg: "RS256") == expected(SHA256.hash(data: Data(token.utf8))))
        #expect(JWS.atHash(token, alg: "ES256") == expected(SHA256.hash(data: Data(token.utf8))))
        #expect(JWS.atHash(token, alg: "PS384") == expected(SHA384.hash(data: Data(token.utf8))))
        #expect(JWS.atHash(token, alg: "ES384") == expected(SHA384.hash(data: Data(token.utf8))))
        #expect(JWS.atHash(token, alg: "RS512") == expected(SHA512.hash(data: Data(token.utf8))))
        #expect(JWS.atHash(token, alg: "EdDSA") == expected(SHA512.hash(data: Data(token.utf8))))
        // The OpenID Connect example (RS256): access token "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" → at_hash "77QmUPtjPfzWtF2AnpK9RQ".
        #expect(JWS.atHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y", alg: "RS256") == "77QmUPtjPfzWtF2AnpK9RQ")
    }
}
