import Foundation

/// The parts of the discovery document this SDK uses.
struct Discovery: Sendable, Equatable {
    var issuer: String
    var authorizationEndpoint: URL
    var tokenEndpoint: URL
    var userinfoEndpoint: URL?
    var jwksURI: URL
    var endSessionEndpoint: URL?
    var revocationEndpoint: URL?
    /// RFC 9207: the authorization response carries `iss`, and a missing one is refused.
    var issParameterSupported: Bool
}

/// Discovery (fetched once, retried after a failure) and the JWKS (cached 10 minutes, fetched
/// again once for an unknown `kid`, unknown kids then ignored for 60 seconds), for one issuer.
actor Provider {
    let issuer: String
    private let http: HTTPClient
    private let allowInsecure: Bool
    private let now: @Sendable () -> Date

    private var discovery: Discovery?
    private var discoveryTask: Task<Discovery, Error>?
    private var keys: [JWK] = []
    private var keysFetchedAt: Date?
    private var keysTask: Task<[JWK], Error>?
    private var missingKids: [String: Date] = [:]

    static let keysTTL: TimeInterval = 600
    static let missingKidTTL: TimeInterval = 60

    init(issuer: String, http: HTTPClient, allowInsecure: Bool, now: @escaping @Sendable () -> Date) {
        self.issuer = issuer
        self.http = http
        self.allowInsecure = allowInsecure
        self.now = now
    }

    func configuration() async throws -> Discovery {
        if let discovery { return discovery }
        if let discoveryTask { return try await discoveryTask.value }
        let task = Task { try await self.fetchDiscovery() }
        discoveryTask = task
        defer { discoveryTask = nil }
        let value = try await task.value
        discovery = value
        return value
    }

    private func fetchDiscovery() async throws -> Discovery {
        guard let url = URL(string: "\(issuer)/.well-known/openid-configuration") else {
            throw NineError(.invalidIssuer, "not a URL: \(issuer)")
        }
        let json: [String: JSONValue]
        do {
            json = try await http.getJSON(url, failure: .discoveryFailed)
        } catch let error as NineError where error.code != .networkError {
            throw NineError(.discoveryFailed, error.message, status: error.status)
        }
        guard let issuer = json["issuer"]?.stringValue else {
            throw NineError(.discoveryFailed, "the discovery document has no issuer")
        }
        // OpenID Connect Discovery 4.3: the document must be for the issuer that was asked.
        guard Issuer.same(issuer, self.issuer) else {
            throw NineError(.invalidIssuer, "the discovery document is for \(issuer), not \(self.issuer)")
        }
        func endpoint(_ name: String, required: Bool) throws -> URL? {
            guard let value = json[name]?.stringValue else {
                if required { throw NineError(.discoveryFailed, "the discovery document has no \(name)") }
                return nil
            }
            guard let url = URL(string: value), Issuer.isSecureEndpoint(url, allowInsecure: allowInsecure) else {
                throw NineError(.discoveryFailed, "\(name) must be an https URL")
            }
            return url
        }
        return Discovery(
            issuer: self.issuer,
            authorizationEndpoint: try endpoint("authorization_endpoint", required: true)!,
            tokenEndpoint: try endpoint("token_endpoint", required: true)!,
            userinfoEndpoint: try endpoint("userinfo_endpoint", required: false),
            jwksURI: try endpoint("jwks_uri", required: true)!,
            endSessionEndpoint: try endpoint("end_session_endpoint", required: false),
            revocationEndpoint: try endpoint("revocation_endpoint", required: false),
            issParameterSupported: json["authorization_response_iss_parameter_supported"]?.boolValue ?? false
        )
    }

    /// The key named `kid`, or nil when the tenant has no such key.
    func key(kid: String?) async throws -> JWK? {
        let current = try await jwks(force: false)
        if let match = Self.find(kid, in: current) { return match }
        let missKey = kid ?? ""
        if let missedAt = missingKids[missKey], now().timeIntervalSince(missedAt) < Self.missingKidTTL { return nil }
        let refreshed = try await jwks(force: true)
        if let match = Self.find(kid, in: refreshed) { return match }
        if missingKids.count > 100 { missingKids.removeAll() }
        missingKids[missKey] = now()
        return nil
    }

    private static func find(_ kid: String?, in keys: [JWK]) -> JWK? {
        if let kid { return keys.first { $0.kid == kid } }
        // A token without a kid can only use the tenant's one key.
        return keys.count == 1 ? keys[0] : nil
    }

    private func jwks(force: Bool) async throws -> [JWK] {
        if !force, let keysFetchedAt, now().timeIntervalSince(keysFetchedAt) < Self.keysTTL { return keys }
        if let keysTask { return try await keysTask.value }
        let task = Task { try await self.fetchKeys() }
        keysTask = task
        defer { keysTask = nil }
        let fetched = try await task.value
        keys = fetched
        keysFetchedAt = now()
        return fetched
    }

    private func fetchKeys() async throws -> [JWK] {
        let config = try await configuration()
        let json = try await http.getJSON(config.jwksURI, failure: .requestFailed)
        guard let list = json["keys"]?.arrayValue else {
            throw NineError(.invalidResponse, "the JWKS has no keys")
        }
        // Keys this SDK can't read (another kty, HMAC never appears) are skipped, not fatal.
        return list.compactMap { value in
            guard let data = try? JSONEncoder().encode(value) else { return nil }
            return try? JSONDecoder().decode(JWK.self, from: data)
        }
    }
}
