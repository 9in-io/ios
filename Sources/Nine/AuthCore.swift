import Foundation

/// What is kept in the credential store for a signed-in user.
struct StoredSession: Codable, Sendable, Equatable {
    var format = 1
    var tokens: TokenSet
    /// Claims of the verified ID token.
    var claims: [String: JSONValue]
    /// Signed in with a private browser session (nothing to end in the browser at sign-out).
    var ephemeral: Bool
}

/// A pending sign-in: what the callback is checked against.
struct PendingSignIn: Sendable {
    let state: String
    let nonce: String
    let verifier: String

    static func make() -> PendingSignIn {
        PendingSignIn(state: Random.string(32), nonce: Random.string(32), verifier: PKCE.makeVerifier())
    }
}

/// The token state of one client. Being an actor, it runs one thing at a time: concurrent
/// `accessToken()` calls share one refresh, and a refresh that finishes after a sign-out or a new
/// sign-in is thrown away instead of bringing old tokens back.
actor AuthCore {
    let config: ResolvedConfiguration
    let provider: Provider
    let http: HTTPClient
    let store: CredentialStore
    let browser: Browser
    let verifier: IDTokenVerifier
    let now: @Sendable () -> Date
    private let relay: ChangeRelay

    private var session: StoredSession?
    private var needsLoad: Bool
    /// Bumped by every sign-in and sign-out; a refresh started under another generation is stale.
    private var generation: UInt64 = 0
    private var version: UInt64 = 0
    private var refreshTask: Task<StoredSession, Error>?
    private var refreshID: UInt64 = 0

    /// Access tokens are refreshed when they expire within this many seconds.
    static let refreshLeeway: TimeInterval = 60

    private struct Superseded: Error {}

    init(config: ResolvedConfiguration, store: CredentialStore, browser: Browser, transport: HTTPTransport,
         now: @escaping @Sendable () -> Date, relay: ChangeRelay, initial: StoredSession?, needsLoad: Bool)
    {
        self.config = config
        self.store = store
        self.browser = browser
        self.now = now
        self.relay = relay
        http = HTTPClient(transport: transport)
        provider = Provider(issuer: config.issuer, http: http, allowInsecure: config.allowInsecureIssuer, now: now)
        verifier = IDTokenVerifier(issuer: config.issuer, clientId: config.clientId, provider: provider, leeway: config.clockSkew, now: now)
        session = initial
        self.needsLoad = needsLoad
    }

    // MARK: Storage

    static func load(_ store: CredentialStore, key: String) throws -> StoredSession? {
        guard let data = try store.read(key) else { return nil }
        // Unreadable data (another format) counts as signed out.
        return try? JSONDecoder().decode(StoredSession.self, from: data)
    }

    private func save(_ session: StoredSession) throws {
        try store.write(try JSONEncoder().encode(session), for: config.storeKey)
    }

    /// Reads the store again when the first read failed (the Keychain is locked until the first
    /// unlock after a restart).
    private func loadIfNeeded() async throws {
        guard needsLoad else { return }
        let loaded = try Self.load(store, key: config.storeKey)
        needsLoad = false
        if loaded != session { await publish(loaded) }
    }

    private func publish(_ new: StoredSession?) async {
        session = new
        version &+= 1
        await relay.publish(new, version: version)
    }

    /// Forgets the session here and in the store. Returns the store's error, if any.
    @discardableResult
    private func clear() async -> Error? {
        generation &+= 1
        refreshTask = nil
        needsLoad = false
        var failure: Error?
        do { try store.delete(config.storeKey) } catch { failure = error }
        if session != nil { await publish(nil) }
        return failure
    }

    // MARK: Sign-in

    func signIn(prompt: String?, loginHint: String?, maxAge: Int?, parameters: [String: String], ephemeral: Bool?) async throws -> NineUser {
        let discovery = try await provider.configuration()
        let pending = PendingSignIn.make()
        let url = authorizationURL(discovery, pending, prompt: prompt, loginHint: loginHint, maxAge: maxAge, parameters: parameters)
        let privateSession = ephemeral ?? config.ephemeral
        let callback = try await browser.open(url, callbackURL: config.redirectURI, ephemeral: privateSession)
        return try await finishSignIn(callback, pending: pending, ephemeral: privateSession)
    }

    /// Parameters a caller can't replace: they carry the security of the flow.
    static let reserved: Set<String> = ["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]

    func authorizationURL(_ discovery: Discovery, _ pending: PendingSignIn, prompt: String?, loginHint: String?, maxAge: Int?, parameters: [String: String]) -> URL {
        var fields: [(String, String)] = parameters.sorted { $0.key < $1.key }.filter { !Self.reserved.contains($0.key) }
        func set(_ name: String, _ value: String?) {
            guard let value else { return }
            fields.removeAll { $0.0 == name }
            fields.append((name, value))
        }
        set("response_type", "code")
        set("client_id", config.clientId)
        set("redirect_uri", config.redirectURI.absoluteString)
        set("scope", config.scope)
        set("state", pending.state)
        set("nonce", pending.nonce)
        set("code_challenge", PKCE.challenge(for: pending.verifier))
        set("code_challenge_method", "S256")
        set("audience", config.audience)
        set("ui_locales", config.locale)
        set("prompt", prompt)
        set("login_hint", loginHint)
        set("max_age", maxAge.map(String.init))
        var components = URLComponents(url: discovery.authorizationEndpoint, resolvingAgainstBaseURL: false)!
        let query = fields.map { "\(FormEncoding.escape($0.0))=\(FormEncoding.escape($0.1))" }.joined(separator: "&")
        components.percentEncodedQuery = [components.percentEncodedQuery, query].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: "&")
        return components.url!
    }

    /// Checks the callback (redirect URI, error, state, RFC 9207 `iss`, code), exchanges the code
    /// with the PKCE verifier, verifies the ID token and keeps the tokens.
    func finishSignIn(_ callback: URL, pending: PendingSignIn, ephemeral: Bool) async throws -> NineUser {
        guard matchesCallback(callback, config.redirectURI) else {
            throw NineError(.invalidCallback, "the browser returned to another URL than the redirect URI")
        }
        var params: [String: String] = [:]
        for item in URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? [] {
            if params[item.name] != nil, ["state", "code", "iss", "error"].contains(item.name) {
                throw NineError(.invalidCallback, "the callback repeats \(item.name)")
            }
            params[item.name] = item.value ?? ""
        }
        let state = params["state"]
        if let error = params["error"] {
            if let state, !constantTimeEquals(state, pending.state) { throw NineError(.invalidState, "state mismatch") }
            throw NineError(NineError.Code(rawValue: error), params["error_description"] ?? error)
        }
        guard let state else { throw NineError(.invalidState, "the callback has no state") }
        guard constantTimeEquals(state, pending.state) else { throw NineError(.invalidState, "state mismatch") }
        let discovery = try await provider.configuration()
        if let iss = params["iss"] {
            guard Issuer.same(iss, config.issuer) else { throw NineError(.invalidIssuer, "unexpected issuer \(iss)") }
        } else if discovery.issParameterSupported {
            throw NineError(.invalidIssuer, "the callback has no iss, which this issuer always sends")
        }
        guard let code = params["code"], !code.isEmpty else { throw NineError(.missingCode, "no authorization code in the callback") }

        let json = try await http.postForm(discovery.tokenEndpoint, [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirectURI.absoluteString),
            ("client_id", config.clientId),
            ("code_verifier", pending.verifier),
        ])
        let tokens = try tokenSet(json, previous: nil)
        guard let idToken = tokens.idToken else { throw NineError(.invalidIdToken, "no ID token in the answer") }
        let claims = try await verifier.verify(idToken, nonce: pending.nonce, accessToken: tokens.accessToken)
        let signedIn = StoredSession(tokens: tokens, claims: claims, ephemeral: ephemeral)
        // Checked and saved before anything is shown: a refused sign-in leaves nothing behind.
        try save(signedIn)
        generation &+= 1
        refreshTask = nil
        needsLoad = false
        await publish(signedIn)
        return NineUser(claims: claims)
    }

    private func tokenSet(_ json: [String: JSONValue], previous: TokenSet?) throws -> TokenSet {
        guard let accessToken = json["access_token"]?.stringValue, !accessToken.isEmpty else {
            throw NineError(.invalidResponse, "no access_token in the answer")
        }
        let type = json["token_type"]?.stringValue ?? "Bearer"
        guard type.caseInsensitiveCompare("Bearer") == .orderedSame else {
            throw NineError(.invalidResponse, "unsupported token_type \(type)")
        }
        let expiresIn = json["expires_in"]?.doubleValue ?? 3600
        return TokenSet(
            accessToken: accessToken,
            tokenType: "Bearer",
            idToken: json["id_token"]?.stringValue,
            // 9in rotates refresh tokens: the new one replaces the old; an answer without one keeps it.
            refreshToken: json["refresh_token"]?.stringValue ?? previous?.refreshToken,
            expiresAt: now().addingTimeInterval(expiresIn),
            scope: json["scope"]?.stringValue ?? previous?.scope
        )
    }

    // MARK: Tokens

    func current() async throws -> StoredSession? {
        try await loadIfNeeded()
        return session
    }

    /// Tokens whose access token is valid for at least a minute, refreshed when needed.
    func validTokens(forceRefresh: Bool) async throws -> TokenSet {
        try await loadIfNeeded()
        for _ in 0..<3 {
            guard let current = session else { throw NineError(.loginRequired, "nobody is signed in") }
            let time = now()
            if !forceRefresh, !current.tokens.isExpired(leeway: Self.refreshLeeway, now: time) { return current.tokens }
            guard current.tokens.refreshToken != nil else {
                if !current.tokens.isExpired(now: time) {
                    if forceRefresh { throw NineError(.loginRequired, "there is no refresh token (add offline_access to the scopes)") }
                    return current.tokens
                }
                await clear()
                throw NineError(.loginRequired, "the access token expired and there is no refresh token")
            }
            do {
                return try await refreshed(from: current).tokens
            } catch is Superseded {
                continue // signed out or in again meanwhile: look at the new state
            }
        }
        throw NineError(.loginRequired, "the session changed while refreshing")
    }

    private func refreshed(from current: StoredSession) async throws -> StoredSession {
        if let refreshTask { return try await refreshTask.value }
        let started = generation
        refreshID &+= 1
        let id = refreshID
        let task = Task<StoredSession, Error> {
            defer { if self.refreshID == id { self.refreshTask = nil } }
            return try await self.performRefresh(current, generation: started)
        }
        refreshTask = task
        return try await task.value
    }

    private func performRefresh(_ current: StoredSession, generation started: UInt64) async throws -> StoredSession {
        guard let refreshToken = current.tokens.refreshToken else { throw NineError(.loginRequired, "there is no refresh token") }
        let discovery = try await provider.configuration()
        let json: [String: JSONValue]
        do {
            json = try await http.postForm(discovery.tokenEndpoint, [
                ("grant_type", "refresh_token"),
                ("refresh_token", refreshToken),
                ("client_id", config.clientId),
            ])
        } catch let error as NineError where error.code == .invalidGrant {
            guard generation == started else { throw Superseded() }
            await clear()
            throw NineError(.loginRequired, "the session ended (\(error.message ?? "the refresh token was refused"))", status: error.status)
        }
        guard generation == started else { throw Superseded() }
        var tokens = try tokenSet(json, previous: current.tokens)
        var claims = current.claims
        tokens.idToken = current.tokens.idToken
        if let idToken = json["id_token"]?.stringValue,
           let verified = try? await verifier.verify(idToken, nonce: nil, accessToken: tokens.accessToken, subject: current.claims["sub"]?.stringValue)
        {
            // The user's claims only ever come from a verified ID token; one that fails is ignored.
            tokens.idToken = idToken
            claims = verified
        }
        guard generation == started else { throw Superseded() }
        let next = StoredSession(tokens: tokens, claims: claims, ephemeral: current.ephemeral)
        // If the Keychain refuses, the new tokens still work for this run of the app.
        try? save(next)
        await publish(next)
        return next
    }

    // MARK: Userinfo, sign-out

    func userInfo() async throws -> NineUser {
        let discovery = try await provider.configuration()
        guard let endpoint = discovery.userinfoEndpoint else { throw NineError(.userinfoFailed, "the issuer has no userinfo endpoint") }
        let token = try await validTokens(forceRefresh: false).accessToken
        let json: [String: JSONValue]
        do {
            json = try await http.getJSON(endpoint, bearer: token, failure: .userinfoFailed)
        } catch let error as NineError where error.status == 401 {
            throw NineError(.invalidToken, error.message, status: 401)
        }
        // OpenID Connect Core 5.3.4: the answer must be about the signed-in user.
        guard let sub = json["sub"]?.stringValue, sub == session?.claims["sub"]?.stringValue else {
            throw NineError(.invalidResponse, "the userinfo answer is about another user")
        }
        return NineUser(claims: json)
    }

    func logoutURL(postLogoutRedirectURI: URL?, state: String?) async throws -> URL {
        try await loadIfNeeded()
        let discovery = try await provider.configuration()
        return logoutURL(discovery, idToken: session?.tokens.idToken, postLogoutRedirectURI: postLogoutRedirectURI ?? config.postLogoutRedirectURI, state: state)
    }

    private func logoutURL(_ discovery: Discovery, idToken: String?, postLogoutRedirectURI: URL?, state: String?) -> URL {
        let endpoint = discovery.endSessionEndpoint ?? URL(string: "\(config.issuer)/oauth/logout")!
        var fields = [("client_id", config.clientId)]
        if let idToken { fields.append(("id_token_hint", idToken)) }
        if let postLogoutRedirectURI { fields.append(("post_logout_redirect_uri", postLogoutRedirectURI.absoluteString)) }
        if let state { fields.append(("state", state)) }
        var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)!
        let query = fields.map { "\(FormEncoding.escape($0.0))=\(FormEncoding.escape($0.1))" }.joined(separator: "&")
        components.percentEncodedQuery = [components.percentEncodedQuery, query].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: "&")
        return components.url!
    }

    /// Forgets the tokens, revokes the refresh token (best effort), and ends the 9in session in
    /// the browser unless `endSession` is false or the sign-in used a private browser session.
    func signOut(endSession: Bool) async throws {
        try? await loadIfNeeded()
        let previous = session
        let storeError = await clear()
        if let previous {
            let discovery = try? await provider.configuration()
            if let endpoint = discovery?.revocationEndpoint {
                let (token, hint) = previous.tokens.refreshToken.map { ($0, "refresh_token") } ?? (previous.tokens.accessToken, "access_token")
                _ = try? await http.postForm(endpoint, [("token", token), ("token_type_hint", hint), ("client_id", config.clientId)])
            }
            if endSession, !previous.ephemeral, let discovery {
                let url = logoutURL(discovery, idToken: previous.tokens.idToken, postLogoutRedirectURI: config.postLogoutRedirectURI, state: Random.string(16))
                do {
                    _ = try await browser.open(url, callbackURL: config.postLogoutRedirectURI ?? config.redirectURI, ephemeral: false)
                } catch let error as NineError where error.code == .canceled {
                    // Without a post-logout redirect URI the user closes 9in's "signed out" page.
                }
            }
        }
        if let storeError { throw storeError }
    }
}

/// Carries state changes from the actor to the client on the main actor.
final class ChangeRelay: @unchecked Sendable {
    private let client = Locked<WeakClient>(WeakClient())

    private struct WeakClient {
        weak var value: NineClient?
    }

    func attach(_ value: NineClient) {
        client.withLock { $0.value = value }
    }

    func publish(_ session: StoredSession?, version: UInt64) async {
        guard let target = client.withLock({ $0.value }) else { return }
        await target.apply(session, version: version)
    }
}
