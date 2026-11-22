import Foundation
import Testing
@testable import Nine

@Suite("ID token verification")
struct IDTokenTests {
    let fake: FakeNine
    let provider: Provider
    let verifier: IDTokenVerifier

    init() {
        fake = FakeNine()
        let clock = fake.clock
        provider = Provider(issuer: fake.issuer, http: HTTPClient(transport: fake), allowInsecure: false, now: { clock.now })
        verifier = IDTokenVerifier(issuer: fake.issuer, clientId: fake.clientId, provider: provider, leeway: 60, now: { clock.now })
    }

    private var key: TestKey { fake.state.current.signingKey }

    private func claims(_ changes: [String: JSONValue?] = [:]) -> [String: JSONValue] {
        let now = fake.clock.now.timeIntervalSince1970.rounded(.down)
        var claims: [String: JSONValue] = [
            "iss": .string(fake.issuer), "sub": "usr_1", "aud": .string(fake.clientId), "azp": .string(fake.clientId),
            "iat": .number(now), "exp": .number(now + 3600), "nonce": "n-123",
        ]
        for (name, value) in changes { claims[name] = value }
        return claims
    }

    private func expectRefused(_ token: String, _ message: String, nonce: String? = "n-123", accessToken: String? = nil, subject: String? = nil, sourceLocation: SourceLocation = #_sourceLocation) async {
        let error = await expectNineError(.invalidIdToken, sourceLocation: sourceLocation) {
            _ = try await verifier.verify(token, nonce: nonce, accessToken: accessToken, subject: subject)
        }
        #expect(error?.message == message, sourceLocation: sourceLocation)
    }

    @Test("A valid ID token signed with each algorithm verifies", arguments: TestKeys.allAlgorithms)
    func everyAlgorithm(alg: String) async throws {
        let signer = TestKeys.make(alg)
        fake.state.withLock { $0.signingKey = signer; $0.jwks = [signer.jwk] }
        let accessToken = "at_xyz"
        var body = claims()
        body["at_hash"] = .string(JWS.atHash(accessToken, alg: alg))
        let verified = try await verifier.verify(TestJWT.sign(body, key: signer), nonce: "n-123", accessToken: accessToken)
        #expect(verified["sub"] == "usr_1")
    }

    @Test("Claims checks")
    func claimChecks() async {
        let now = fake.clock.now.timeIntervalSince1970.rounded(.down)
        await expectRefused(TestJWT.sign(claims(["iss": "https://evil.example"]), key: key), "issuer mismatch")
        await expectRefused(TestJWT.sign(claims(["iss": nil]), key: key), "issuer mismatch")
        await expectRefused(TestJWT.sign(claims(["aud": "other_app", "azp": nil]), key: key), "audience mismatch")
        await expectRefused(TestJWT.sign(claims(["aud": nil]), key: key), "audience mismatch")
        await expectRefused(TestJWT.sign(claims(["aud": [.string(fake.clientId), "other"], "azp": "other"]), key: key), "authorized party mismatch")
        await expectRefused(TestJWT.sign(claims(["aud": [.string(fake.clientId), "other"], "azp": nil]), key: key), "authorized party mismatch")
        await expectRefused(TestJWT.sign(claims(["azp": "someone_else"]), key: key), "authorized party mismatch")
        await expectRefused(TestJWT.sign(claims(["exp": .number(now - 61)]), key: key), "token expired")
        await expectRefused(TestJWT.sign(claims(["exp": nil]), key: key), "no expiry")
        await expectRefused(TestJWT.sign(claims(["exp": "tomorrow"]), key: key), "no expiry")
        await expectRefused(TestJWT.sign(claims(["nbf": .number(now + 61)]), key: key), "token not yet valid")
        await expectRefused(TestJWT.sign(claims(["sub": nil]), key: key), "missing subject")
        await expectRefused(TestJWT.sign(claims(["sub": ""]), key: key), "missing subject")
        await expectRefused(TestJWT.sign(claims(["nonce": "other"]), key: key), "nonce mismatch")
        await expectRefused(TestJWT.sign(claims(["nonce": nil]), key: key), "nonce mismatch")
        await expectRefused(TestJWT.sign(claims(["at_hash": "AAAAAAAAAAAAAAAAAAAAAA"]), key: key), "at_hash does not match the access token", accessToken: "at_1")
        await expectRefused(TestJWT.sign(claims(), key: key), "the token is for another user", subject: "usr_2")
    }

    @Test("Within the clock skew, times pass; an array audience with the right azp passes")
    func leeway() async throws {
        let now = fake.clock.now.timeIntervalSince1970.rounded(.down)
        _ = try await verifier.verify(TestJWT.sign(claims(["exp": .number(now - 59), "nbf": .number(now + 59)]), key: key), nonce: "n-123", accessToken: nil)
        _ = try await verifier.verify(TestJWT.sign(claims(["aud": [.string(fake.clientId), "https://api.acme.com"]]), key: key), nonce: "n-123", accessToken: nil)
        _ = try await verifier.verify(TestJWT.sign(claims(["azp": nil]), key: key), nonce: "n-123", accessToken: nil)
        // No nonce expected (a refresh): a nonce in the token is not checked.
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: nil, accessToken: nil)
        // A trailing slash on iss is the same issuer.
        _ = try await verifier.verify(TestJWT.sign(claims(["iss": .string(fake.issuer + "/")]), key: key), nonce: "n-123", accessToken: nil)
    }

    @Test("Header checks: typ, alg none, HMAC, malformed")
    func headerChecks() async {
        await expectRefused(TestJWT.sign(claims(), key: key, header: ["typ": "at+jwt"]), "an access token is not an ID token")
        await expectRefused(TestJWT.sign(claims(), key: key, header: ["typ": "application/at+jwt"]), "an access token is not an ID token")
        await expectRefused(TestJWT.unsigned(claims()), "unsupported algorithm none")
        await expectRefused(TestJWT.unsigned(claims(), header: ["typ": "JWT"]), "unsupported algorithm none")
        await expectRefused(TestJWT.sign(claims(), key: key, header: ["alg": "HS256"]), "unsupported algorithm HS256")
        await expectRefused("not-a-jwt", "malformed ID token")
        var token = TestJWT.sign(claims(), key: key)
        token.removeLast(4)
        token += "AAAA"
        await expectRefused(token, "bad signature")
        // The payload changed after signing.
        let parts = TestJWT.sign(claims(), key: key).split(separator: ".")
        await expectRefused("\(parts[0]).\(TestJWT.encode(claims(["sub": "usr_admin"]))).\(parts[2])", "bad signature")
    }

    @Test("A key whose alg differs from the token's is refused")
    func keyAlgorithm() async {
        let rs = fake.state.current.signingKey
        let ps = TestKeys.make("PS256", kid: rs.kid) // same RSA key pair, same kid
        await expectRefused(TestJWT.sign(claims(), key: ps), "algorithm does not match the key")
    }

    @Test("Unknown kid: one JWKS refetch, then ignored for 60 seconds")
    func unknownKid() async throws {
        let stranger = TestKeys.make("ES256")
        let token = TestJWT.sign(claims(), key: stranger)
        await expectRefused(token, "unknown signing key")
        #expect(fake.requests("/.well-known/jwks.json").count == 2) // first load + one refetch
        await expectRefused(token, "unknown signing key")
        #expect(fake.requests("/.well-known/jwks.json").count == 2) // throttled
        fake.clock.advance(61)
        await expectRefused(token, "unknown signing key")
        #expect(fake.requests("/.well-known/jwks.json").count == 3)
        // Known keys are served from the cache meanwhile.
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
        #expect(fake.requests("/.well-known/jwks.json").count == 3)
    }

    @Test("A key added after a rotation is found with one refetch")
    func rotation() async throws {
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
        let next = TestKeys.make("EdDSA")
        fake.state.withLock { $0.jwks.append(next.jwk) }
        _ = try await verifier.verify(TestJWT.sign(claims(), key: next), nonce: "n-123", accessToken: nil)
        #expect(fake.requests("/.well-known/jwks.json").count == 2)
    }

    @Test("The JWKS is cached for 10 minutes")
    func jwksCache() async throws {
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
        fake.clock.advance(599)
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
        #expect(fake.requests("/.well-known/jwks.json").count == 1)
        fake.clock.advance(2)
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
        #expect(fake.requests("/.well-known/jwks.json").count == 2)
    }

    @Test("Keys it can't read are skipped, not fatal")
    func unreadableKeys() async throws {
        fake.state.withLock { $0.jwks.insert(["kty": "oct", "kid": "hmac"], at: 0); $0.jwks.insert(["nonsense": true], at: 0) }
        _ = try await verifier.verify(TestJWT.sign(claims(), key: key), nonce: "n-123", accessToken: nil)
    }
}
