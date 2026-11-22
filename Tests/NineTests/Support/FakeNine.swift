import Foundation
import Testing
@testable import Nine

/// A clock tests can move.
final class TestClock: @unchecked Sendable {
    private let value: Locked<Date>
    init(_ start: Date = Date()) { value = Locked(start) }
    var now: Date { value.current }
    func advance(_ seconds: TimeInterval) { value.withLock { $0 = $0.addingTimeInterval(seconds) } }
}

/// A fake 9in tenant: the HTTP endpoints (discovery, JWKS, token with PKCE and refresh rotation,
/// userinfo, revocation) and the browser step (a user who signs in on the hosted page).
final class FakeNine: HTTPTransport, Browser, @unchecked Sendable {
    struct Request: Sendable {
        let method: String
        let path: String
        let form: [String: String]
        let headers: [String: String]
    }

    struct Grant {
        let clientId: String
        let redirectURI: String
        let challenge: String
        let nonce: String?
        let scope: String
    }

    struct BrowserVisit: Sendable {
        let url: URL
        let callbackURL: URL
        let ephemeral: Bool
        var query: [String: String] {
            Dictionary(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.map { ($0.name, $0.value ?? "") } ?? [], uniquingKeysWith: { a, _ in a })
        }
    }

    struct State {
        var signingKey: TestKey
        var jwks: [[String: JSONValue]]
        /// Members added to (or, with `.null`, removed from) the discovery document.
        var discovery: [String: JSONValue] = [:]
        var discoveryStatus = 200
        var requests: [Request] = []
        var codes: [String: Grant] = [:]
        var refreshTokens: [String: (sub: String, used: Bool)] = [:]
        var accessTokens: Set<String> = []
        var visits: [BrowserVisit] = []
        /// Answers the token endpoint gives before working normally: (status, body).
        var tokenFailures: [(Int, [String: JSONValue])] = []
        /// Thrown by the transport for the token endpoint (a network failure).
        var tokenNetworkError: URLError?
        var tokenDelay: UInt64 = 0
        var accessTokenTTL: Double = 3600
        var sub = "usr_8k2"
        var email = "jane@example.com"
        var userinfoSub: String?
        var idTokenOnRefresh = true
        var rotate = true
        /// Changes the ID token before it is signed.
        var idToken: (@Sendable (inout [String: JSONValue], inout [String: JSONValue]) -> Void)?
        /// Changes the callback the browser returns (`authorize URL`, `callback`) → callback.
        var callback: (@Sendable (URL, URL) -> URL)?
        var browserError: Error?
        var revokeStatus = 200
    }

    let issuer: String
    let clientId = "app_test"
    let clock: TestClock
    let state: Locked<State>

    init(issuer: String = "https://acme.9in.test", clock: TestClock = TestClock(), alg: String = "RS256") {
        self.issuer = issuer
        self.clock = clock
        let key = TestKeys.make(alg)
        state = Locked(State(signingKey: key, jwks: [key.jwk]))
    }

    var requests: [Request] { state.current.requests }
    var visits: [BrowserVisit] { state.current.visits }
    func requests(_ path: String) -> [Request] { requests.filter { $0.path == path } }

    /// A client of this tenant with an in-memory store unless one is given.
    func client(store: CredentialStore = MemoryCredentialStore(), redirectURI: String = "com.example.app:/callback",
                configure: (inout NineClient.Configuration) -> Void = { _ in }) -> NineClient
    {
        var configuration = NineClient.Configuration(issuer: issuer, clientId: clientId, redirectURI: redirectURI)
        configure(&configuration)
        let clock = clock
        return NineClient(configuration: configuration, store: store, browser: self, transport: self, now: { clock.now })
    }

    // MARK: HTTP

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let url = request.url!
        let form = request.httpBody.map(FormEncoding.decode) ?? [:]
        let recorded = Request(method: request.httpMethod ?? "GET", path: url.path, form: form, headers: request.allHTTPHeaderFields ?? [:])
        state.withLock { $0.requests.append(recorded) }
        let (status, body) = try await handle(recorded)
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        return (try JSONEncoder().encode(body), response)
    }

    private func handle(_ request: Request) async throws -> (Int, JSONValue) {
        switch (request.method, request.path) {
        case ("GET", "/.well-known/openid-configuration"):
            let current = state.current
            var document: [String: JSONValue] = [
                "issuer": .string(issuer),
                "authorization_endpoint": .string("\(issuer)/oauth/authorize"),
                "token_endpoint": .string("\(issuer)/oauth/token"),
                "userinfo_endpoint": .string("\(issuer)/oauth/userinfo"),
                "jwks_uri": .string("\(issuer)/.well-known/jwks.json"),
                "end_session_endpoint": .string("\(issuer)/oauth/logout"),
                "revocation_endpoint": .string("\(issuer)/oauth/revoke"),
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": true,
            ]
            for (name, value) in current.discovery { document[name] = value.isNull ? nil : value }
            return (current.discoveryStatus, current.discoveryStatus == 200 ? .object(document) : ["error": "server_error"])
        case ("GET", "/.well-known/jwks.json"):
            return (200, ["keys": .array(state.current.jwks.map(JSONValue.object))])
        case ("POST", "/oauth/token"):
            let delay = state.current.tokenDelay
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
            if let error = state.current.tokenNetworkError { throw error }
            if let failure = state.withLock({ $0.tokenFailures.isEmpty ? nil : $0.tokenFailures.removeFirst() }) {
                return (failure.0, .object(failure.1))
            }
            return token(request.form)
        case ("GET", "/oauth/userinfo"):
            let bearer = request.headers["Authorization"]?.replacingOccurrences(of: "Bearer ", with: "") ?? ""
            let current = state.current
            guard current.accessTokens.contains(bearer) else { return (401, ["error": "invalid_token", "error_description": "token is not active"]) }
            return (200, ["sub": .string(current.userinfoSub ?? current.sub), "email": .string(current.email), "email_verified": true])
        case ("POST", "/oauth/revoke"):
            let status = state.current.revokeStatus
            return (status, status == 200 ? [:] : ["error": "server_error"])
        default:
            return (404, ["error": "not_found"])
        }
    }

    private func error(_ code: String, _ description: String, status: Int = 400) -> (Int, JSONValue) {
        (status, ["error": .string(code), "error_description": .string(description)])
    }

    private func token(_ form: [String: String]) -> (Int, JSONValue) {
        guard form["client_id"] == clientId else { return error("invalid_client", "unknown client", status: 401) }
        switch form["grant_type"] {
        case "authorization_code":
            guard let code = form["code"], let grant = state.withLock({ $0.codes.removeValue(forKey: code) }) else {
                return error("invalid_grant", "unknown or used code")
            }
            guard form["redirect_uri"] == grant.redirectURI else { return error("invalid_grant", "redirect_uri mismatch") }
            guard let verifier = form["code_verifier"], PKCE.challenge(for: verifier) == grant.challenge else {
                return error("invalid_grant", "PKCE verification failed")
            }
            return (200, issue(nonce: grant.nonce, scope: grant.scope, idToken: true))
        case "refresh_token":
            guard let token = form["refresh_token"] else { return error("invalid_request", "refresh_token is required") }
            let valid = state.withLock { state -> Bool in
                guard let record = state.refreshTokens[token], !record.used else { return false }
                if state.rotate { state.refreshTokens[token]?.used = true }
                return true
            }
            guard valid else { return error("invalid_grant", "refresh token is invalid, expired or revoked") }
            return (200, issue(nonce: nil, scope: "openid profile email offline_access", idToken: state.current.idTokenOnRefresh, rotatedFrom: token))
        default:
            return error("unsupported_grant_type", "unsupported grant")
        }
    }

    private func issue(nonce: String?, scope: String, idToken includeIDToken: Bool, rotatedFrom: String? = nil) -> JSONValue {
        let current = state.current
        let accessToken = "at_\(UUID().uuidString)"
        let now = clock.now.timeIntervalSince1970.rounded(.down)
        var body: [String: JSONValue] = [
            "access_token": .string(accessToken),
            "token_type": "Bearer",
            "expires_in": .number(current.accessTokenTTL),
            "scope": .string(scope),
        ]
        var refreshToken: String?
        if scope.split(separator: " ").contains("offline_access") {
            if rotatedFrom != nil, !current.rotate {
                refreshToken = nil
            } else {
                refreshToken = "rt_\(UUID().uuidString)"
                body["refresh_token"] = .string(refreshToken!)
            }
        }
        if includeIDToken {
            var claims: [String: JSONValue] = [
                "iss": .string(issuer), "sub": .string(current.sub), "aud": .string(clientId), "azp": .string(clientId),
                "iat": .number(now), "exp": .number(now + 3600), "auth_time": .number(now), "sid": "sid_1", "amr": ["pwd"],
                "at_hash": .string(JWS.atHash(accessToken, alg: current.signingKey.alg)),
                "email": .string(current.email), "email_verified": true, "name": "Jane Doe",
            ]
            if let nonce { claims["nonce"] = .string(nonce) }
            var header: [String: JSONValue] = [:]
            current.idToken?(&claims, &header)
            body["id_token"] = .string(TestJWT.sign(claims, key: current.signingKey, header: header))
        }
        state.withLock { state in
            state.accessTokens.insert(accessToken)
            if let refreshToken { state.refreshTokens[refreshToken] = (current.sub, false) }
        }
        return .object(body)
    }

    // MARK: Browser

    func open(_ url: URL, callbackURL: URL, ephemeral: Bool) async throws -> URL {
        let visit = BrowserVisit(url: url, callbackURL: callbackURL, ephemeral: ephemeral)
        state.withLock { $0.visits.append(visit) }
        if let error = state.current.browserError { throw error }
        let query = visit.query
        if url.path == "/oauth/logout" {
            guard let redirect = query["post_logout_redirect_uri"] else {
                throw NineError(.canceled, "the user closed the signed-out page")
            }
            var components = URLComponents(string: redirect)!
            components.queryItems = query["state"].map { [URLQueryItem(name: "state", value: $0)] }
            return components.url!
        }
        #expect(url.path == "/oauth/authorize")
        #expect(query["response_type"] == "code")
        #expect(query["client_id"] == clientId)
        #expect(query["redirect_uri"] == callbackURL.absoluteString)
        #expect(query["code_challenge_method"] == "S256")
        let code = "code_\(UUID().uuidString)"
        state.withLock {
            $0.codes[code] = Grant(clientId: query["client_id"] ?? "", redirectURI: query["redirect_uri"] ?? "", challenge: query["code_challenge"] ?? "", nonce: query["nonce"], scope: query["scope"] ?? "openid")
        }
        var components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "code", value: code), URLQueryItem(name: "state", value: query["state"]), URLQueryItem(name: "iss", value: issuer)]
        let callback = components.url!
        return state.current.callback?(url, callback) ?? callback
    }
}

/// Replaces or removes query parameters of a URL.
func with(_ url: URL, _ changes: [String: String?]) -> URL {
    var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
    var items = components.queryItems ?? []
    for (name, value) in changes {
        items.removeAll { $0.name == name }
        if let value { items.append(URLQueryItem(name: name, value: value)) }
    }
    components.queryItems = items
    return components.url!
}

/// Fails the test unless `body` throws a `NineError` with `code`; returns the error.
@discardableResult
func expectNineError(_ code: NineError.Code, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void) async -> NineError? {
    do {
        try await body()
        Issue.record("expected NineError \(code), nothing was thrown", sourceLocation: sourceLocation)
    } catch let error as NineError {
        #expect(error.code == code, "got \(error)", sourceLocation: sourceLocation)
        return error
    } catch {
        Issue.record("expected NineError \(code), got \(error)", sourceLocation: sourceLocation)
    }
    return nil
}
