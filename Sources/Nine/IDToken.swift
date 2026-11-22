import Foundation

/// Verifies ID tokens: signature against the tenant's JWKS, then `iss`, `aud`, `azp`, `exp`,
/// `nbf`, `sub`, `nonce` and `at_hash` (OpenID Connect Core 3.1.3.7).
struct IDTokenVerifier: Sendable {
    let issuer: String
    let clientId: String
    let provider: Provider
    let leeway: TimeInterval
    let now: @Sendable () -> Date

    private static let accessTokenTypes: Set<String> = ["at+jwt", "application/at+jwt"]

    /// The verified claims. `nonce` is required to match when given (sign-in), `accessToken` is
    /// checked against `at_hash` when the token has one, and `subject` must match when given
    /// (an ID token from a refresh belongs to the same user).
    func verify(_ token: String, nonce: String?, accessToken: String?, subject: String? = nil) async throws -> [String: JSONValue] {
        func fail(_ message: String) -> NineError { NineError(.invalidIdToken, message) }

        guard let jwt = JWT(token) else { throw fail("malformed ID token") }
        if let typ = jwt.header["typ"]?.stringValue, Self.accessTokenTypes.contains(typ.lowercased()) {
            throw fail("an access token is not an ID token")
        }
        guard let alg = jwt.header["alg"]?.stringValue, JWS.algorithms.contains(alg) else {
            throw fail("unsupported algorithm \(jwt.header["alg"]?.stringValue ?? "none")")
        }
        guard let key = try await provider.key(kid: jwt.header["kid"]?.stringValue) else {
            throw fail("unknown signing key")
        }
        do {
            try JWS.verify(alg: alg, jwk: key, input: jwt.signingInput, signature: jwt.signature)
        } catch let failure as JWS.Failure {
            switch failure {
            case .algorithmMismatch: throw fail("algorithm does not match the key")
            case .wrongKeyType: throw fail("the key does not fit the algorithm")
            case .weakKey: throw fail("RSA keys must have at least 2048 bits")
            case .badKey: throw fail("unreadable signing key")
            case .unsupportedAlgorithm: throw fail("unsupported algorithm \(alg)")
            case .badSignature: throw fail("bad signature")
            }
        }

        let claims = jwt.claims
        guard let iss = claims["iss"]?.stringValue, Issuer.same(iss, issuer) else { throw fail("issuer mismatch") }
        let audiences: [String]
        switch claims["aud"] {
        case let .string(value)?: audiences = [value]
        case let .array(values)?: audiences = values.compactMap(\.stringValue)
        default: audiences = []
        }
        guard audiences.contains(clientId) else { throw fail("audience mismatch") }
        if audiences.count > 1 || claims["azp"] != nil {
            guard claims["azp"]?.stringValue == clientId else { throw fail("authorized party mismatch") }
        }
        let time = now().timeIntervalSince1970
        guard let exp = claims["exp"]?.doubleValue else { throw fail("no expiry") }
        guard exp + leeway >= time else { throw fail("token expired") }
        if let nbf = claims["nbf"]?.doubleValue, nbf - leeway > time { throw fail("token not yet valid") }
        guard let sub = claims["sub"]?.stringValue, !sub.isEmpty else { throw fail("missing subject") }
        if let subject, sub != subject { throw fail("the token is for another user") }
        if let nonce {
            guard let value = claims["nonce"]?.stringValue, constantTimeEquals(value, nonce) else { throw fail("nonce mismatch") }
        }
        if let accessToken, let atHash = claims["at_hash"]?.stringValue {
            guard constantTimeEquals(atHash, JWS.atHash(accessToken, alg: alg)) else { throw fail("at_hash does not match the access token") }
        }
        return claims
    }
}
