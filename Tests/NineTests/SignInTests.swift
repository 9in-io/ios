import Foundation
import Testing
@testable import Nine

@Suite("Sign-in: authorization code + PKCE through the browser seam")
struct SignInTests {
    @Test("Signs in: PKCE, state, nonce, iss, ID token; the tokens are saved")
    func signIn() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let nine = fake.client(store: store) { $0.audience = "https://api.acme.com"; $0.locale = "de" }
        #expect(!nine.isSignedIn)

        let user = try await nine.signIn(loginHint: "jane@example.com")

        #expect(user.sub == "usr_8k2")
        #expect(user.email == "jane@example.com")
        #expect(user.name == "Jane Doe")
        #expect(nine.isSignedIn)
        #expect(nine.user == user)
        let tokens = try #require(nine.tokens)
        #expect(tokens.refreshToken != nil)
        #expect(tokens.idToken != nil)
        #expect(tokens.scope == "openid profile email offline_access")

        let visit = try #require(fake.visits.first)
        #expect(visit.ephemeral == false)
        #expect(visit.callbackURL.absoluteString == "com.example.app:/callback")
        let query = visit.query
        #expect(query["scope"] == "openid profile email offline_access")
        #expect(query["audience"] == "https://api.acme.com")
        #expect(query["ui_locales"] == "de")
        #expect(query["login_hint"] == "jane@example.com")
        #expect(query["prompt"] == nil)
        #expect(query["state"]?.count == 43)
        #expect(query["nonce"]?.count == 43)
        #expect(query["code_challenge"]?.count == 43)

        // The code was exchanged with the verifier that matches the challenge.
        let exchange = try #require(fake.requests("/oauth/token").first)
        #expect(exchange.form["grant_type"] == "authorization_code")
        #expect(exchange.form["client_id"] == fake.clientId)
        #expect(exchange.form["redirect_uri"] == "com.example.app:/callback")
        #expect(PKCE.challenge(for: exchange.form["code_verifier"] ?? "") == query["code_challenge"])
        #expect(exchange.headers["Authorization"] == nil) // public client: no secret

        // Saved in the store, readable by a new client.
        let saved = try #require(try store.read("\(fake.issuer) \(fake.clientId)"))
        let session = try JSONDecoder().decode(StoredSession.self, from: saved)
        #expect(session.tokens == tokens)
        #expect(fake.client(store: store).user == user)
    }

    @Test("signUp opens the sign-up form (prompt=create)")
    func signUp() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signUp(loginHint: "new@example.com")
        #expect(fake.visits.first?.query["prompt"] == "create")
        #expect(fake.visits.first?.query["login_hint"] == "new@example.com")
    }

    @Test("Prompt, max_age, ephemeral and extra parameters; extras never replace the reserved ones")
    func parameters() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signIn(prompt: .login, maxAge: 300, parameters: ["state": "attacker", "code_challenge": "x", "redirect_uri": "evil:/", "acr_values": "mfa", "prompt": "none"], ephemeral: true)
        let visit = try #require(fake.visits.first)
        #expect(visit.ephemeral)
        #expect(visit.query["prompt"] == "login")
        #expect(visit.query["max_age"] == "300")
        #expect(visit.query["acr_values"] == "mfa")
        #expect(visit.query["state"] != "attacker")
        #expect(visit.query["code_challenge"] != "x")
        #expect(visit.query["redirect_uri"] == "com.example.app:/callback")
        #expect(nine.isSignedIn)
    }

    @Test("prefersEphemeralWebBrowserSession applies to every sign-in")
    func ephemeralConfiguration() async throws {
        let fake = FakeNine()
        let nine = fake.client { $0.prefersEphemeralWebBrowserSession = true }
        try await nine.signIn()
        #expect(fake.visits.first?.ephemeral == true)
    }

    @Test("Every sign-in uses a new state, nonce and verifier")
    func freshValues() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signIn()
        try await nine.signIn()
        let (first, second) = (fake.visits[0].query, fake.visits[1].query)
        #expect(first["state"] != second["state"])
        #expect(first["nonce"] != second["nonce"])
        #expect(first["code_challenge"] != second["code_challenge"])
    }

    /// Signs in with the callback changed by `tamper`, and checks nothing was saved.
    private func refusedCallback(_ code: NineError.Code, message: String? = nil, sourceLocation: SourceLocation = #_sourceLocation, _ tamper: @escaping @Sendable (URL, URL) -> URL) async {
        let fake = FakeNine()
        fake.state.withLock { $0.callback = tamper }
        let store = MemoryCredentialStore()
        let nine = fake.client(store: store)
        let error = await expectNineError(code, sourceLocation: sourceLocation) { try await nine.signIn() }
        if let message { #expect(error?.message == message, sourceLocation: sourceLocation) }
        #expect(!nine.isSignedIn, sourceLocation: sourceLocation)
        #expect(try! store.read("\(fake.issuer) \(fake.clientId)") == nil, sourceLocation: sourceLocation)
        #expect(fake.requests("/oauth/token").isEmpty, "the code must not be spent", sourceLocation: sourceLocation)
    }

    @Test("State checks: wrong, missing, repeated")
    func stateChecks() async {
        await refusedCallback(.invalidState, message: "state mismatch") { _, callback in with(callback, ["state": "forged"]) }
        await refusedCallback(.invalidState, message: "the callback has no state") { _, callback in with(callback, ["state": nil]) }
        await refusedCallback(.invalidState, message: "state mismatch") { _, callback in with(callback, ["state": ""]) }
        await refusedCallback(.invalidCallback) { _, callback in URL(string: callback.absoluteString + "&state=second")! }
        await refusedCallback(.invalidCallback) { _, callback in URL(string: callback.absoluteString + "&code=second")! }
    }

    @Test("A callback from an earlier sign-in is refused (state is single-use)")
    func replay() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        let captured = Locked<URL?>(nil)
        fake.state.withLock { $0.callback = { _, callback in captured.withLock { $0 = callback }; return callback } }
        try await nine.signIn()
        let old = try #require(captured.current)
        fake.state.withLock { $0.callback = { _, _ in old } }
        await expectNineError(.invalidState) { try await nine.signIn() }
        #expect(fake.requests("/oauth/token").count == 1)
    }

    @Test("RFC 9207 iss: a wrong one is refused; a missing one too when the issuer advertises it")
    func issChecks() async throws {
        await refusedCallback(.invalidIssuer, message: "unexpected issuer https://evil.example") { _, callback in with(callback, ["iss": "https://evil.example"]) }
        await refusedCallback(.invalidIssuer) { _, callback in with(callback, ["iss": nil]) }

        // An issuer that doesn't advertise the parameter may leave it out.
        let fake = FakeNine()
        fake.state.withLock { $0.discovery["authorization_response_iss_parameter_supported"] = false; $0.callback = { _, callback in with(callback, ["iss": nil]) } }
        try await fake.client().signIn()
        // …but a wrong one is always refused.
        let other = FakeNine()
        other.state.withLock { $0.discovery["authorization_response_iss_parameter_supported"] = .null; $0.callback = { _, callback in with(callback, ["iss": "https://evil.example"]) } }
        await expectNineError(.invalidIssuer) { try await other.client().signIn() }
        // A trailing slash is the same issuer.
        let slash = FakeNine()
        slash.state.withLock { $0.callback = { _, callback in with(callback, ["iss": slash.issuer + "/"]) } }
        try await slash.client().signIn()
    }

    @Test("Errors from 9in come through with their code and description")
    func errorCallback() async {
        await refusedCallback(.accessDenied, message: "The user declined") { _, callback in
            with(callback, ["code": nil, "iss": nil, "error": "access_denied", "error_description": "The user declined"])
        }
        await refusedCallback("login_required") { _, callback in with(callback, ["code": nil, "error": "login_required"]) }
        // An error carrying another sign-in's state is a state problem.
        await refusedCallback(.invalidState) { _, callback in with(callback, ["code": nil, "error": "access_denied", "state": "forged"]) }
    }

    @Test("A callback without a code, or to another URL, is refused")
    func badCallbacks() async {
        await refusedCallback(.missingCode) { _, callback in with(callback, ["code": nil]) }
        await refusedCallback(.missingCode) { _, callback in with(callback, ["code": ""]) }
        await refusedCallback(.invalidCallback) { _, callback in URL(string: callback.absoluteString.replacingOccurrences(of: "/callback", with: "/elsewhere"))! }
        await refusedCallback(.invalidCallback) { _, callback in URL(string: callback.absoluteString.replacingOccurrences(of: "com.example.app:", with: "com.evil.app:"))! }
    }

    @Test("Callback matching: scheme, host and path of the redirect URI")
    func callbackMatching() {
        let custom = URL(string: "com.acme.app:/callback")!
        #expect(matchesCallback(URL(string: "com.acme.app:/callback?code=1&state=2")!, custom))
        #expect(matchesCallback(URL(string: "COM.ACME.APP:/callback?code=1")!, custom))
        #expect(!matchesCallback(URL(string: "com.acme.app:/other?code=1")!, custom))
        #expect(!matchesCallback(URL(string: "com.acme.app://evil/callback?code=1")!, custom))
        let https = URL(string: "https://app.acme.com/callback")!
        #expect(matchesCallback(URL(string: "https://app.acme.com/callback?code=1")!, https))
        #expect(matchesCallback(URL(string: "https://APP.acme.com/callback")!, https))
        #expect(!matchesCallback(URL(string: "https://evil.com/callback?code=1")!, https))
        #expect(!matchesCallback(URL(string: "https://app.acme.com:8443/callback")!, https))
        let loopback = URL(string: "http://127.0.0.1:8931/callback")!
        #expect(matchesCallback(URL(string: "http://127.0.0.1:8931/callback?code=1")!, loopback))
        #expect(!matchesCallback(URL(string: "http://127.0.0.1:8932/callback?code=1")!, loopback))
    }

    @Test("What the system browser can return to")
    func callbackKinds() throws {
        #expect(try CallbackMatch(URL(string: "com.acme.app:/callback")!) == .customScheme("com.acme.app"))
        #expect(try CallbackMatch(URL(string: "https://app.acme.com/auth/callback")!) == .https(host: "app.acme.com", path: "/auth/callback"))
        #expect(try CallbackMatch(URL(string: "http://127.0.0.1:8931/callback")!) == .loopback)
        #expect(throws: NineError.self) { try CallbackMatch(URL(string: "http://app.acme.com/callback")!) }
    }

    @Test("A token endpoint error is passed through and nothing is saved")
    func tokenError() async throws {
        let fake = FakeNine()
        fake.state.withLock { $0.tokenFailures = [(400, ["error": "invalid_grant", "error_description": "PKCE verification failed"])] }
        let store = MemoryCredentialStore()
        let nine = fake.client(store: store)
        let error = await expectNineError(.invalidGrant) { try await nine.signIn() }
        #expect(error?.status == 400)
        #expect(error?.message == "PKCE verification failed")
        #expect(!nine.isSignedIn)
        #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)

        fake.state.withLock { $0.tokenFailures = [(502, [:])] }
        let gateway = await expectNineError(.requestFailed) { try await nine.signIn() }
        #expect(gateway?.status == 502)
    }

    @Test("Bad token answers are refused", arguments: [
        ["token_type": "Bearer"] as [String: JSONValue],
        ["access_token": "", "token_type": "Bearer"],
        ["access_token": "x", "token_type": "DPoP"],
    ])
    func badTokenAnswers(body: [String: JSONValue]) async {
        let fake = FakeNine()
        fake.state.withLock { $0.tokenFailures = [(200, body)] }
        await expectNineError(.invalidResponse) { try await fake.client().signIn() }
    }

    @Test("A token answer without an ID token is refused")
    func noIDToken() async {
        let fake = FakeNine()
        fake.state.withLock { $0.tokenFailures = [(200, ["access_token": "at", "token_type": "bearer", "expires_in": 3600])] }
        let nine = fake.client()
        await expectNineError(.invalidIdToken) { try await nine.signIn() }
        #expect(!nine.isSignedIn)
    }

    @Test("A bad ID token stops the sign-in and nothing is saved")
    func badIDToken() async throws {
        let cases: [@Sendable (inout [String: JSONValue], inout [String: JSONValue]) -> Void] = [
            { claims, _ in claims["nonce"] = "replayed" },
            { claims, _ in claims["aud"] = "another_app" },
            { claims, _ in claims["iss"] = "https://evil.example" },
            { claims, _ in claims["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" },
            { claims, _ in claims["exp"] = 1000 },
            { _, header in header["kid"] = "unknown" },
        ]
        for change in cases {
            let fake = FakeNine()
            fake.state.withLock { $0.idToken = change }
            let store = MemoryCredentialStore()
            let nine = fake.client(store: store)
            await expectNineError(.invalidIdToken) { try await nine.signIn() }
            #expect(!nine.isSignedIn)
            #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)
        }
    }

    @Test("Closing the sheet throws canceled")
    func canceled() async {
        let fake = FakeNine()
        fake.state.withLock { $0.browserError = NineError(.canceled, "the user closed the sign-in sheet") }
        let nine = fake.client()
        await expectNineError(.canceled) { try await nine.signIn() }
        #expect(!nine.isSignedIn)
    }

    @Test("Discovery: a document for another issuer is refused")
    func discoveryIssuer() async {
        let fake = FakeNine()
        fake.state.withLock { $0.discovery["issuer"] = "https://evil.example" }
        await expectNineError(.invalidIssuer) { try await fake.client().signIn() }
        #expect(fake.visits.isEmpty)
    }

    @Test("Discovery: http endpoints and missing ones are refused")
    func discoveryEndpoints() async {
        for change: [String: JSONValue] in [["token_endpoint": "http://acme.9in.test/oauth/token"], ["authorization_endpoint": .null], ["jwks_uri": "not a url"]] {
            let fake = FakeNine()
            fake.state.withLock { $0.discovery = change }
            await expectNineError(.discoveryFailed) { try await fake.client().signIn() }
            #expect(fake.visits.isEmpty)
        }
    }

    @Test("Discovery: a failure is not cached, a success is")
    func discoveryRetry() async throws {
        let fake = FakeNine()
        fake.state.withLock { $0.discoveryStatus = 503 }
        let nine = fake.client()
        let error = await expectNineError(.discoveryFailed) { try await nine.signIn() }
        #expect(error?.status == 503)
        fake.state.withLock { $0.discoveryStatus = 200 }
        try await nine.signIn()
        try await nine.signIn()
        #expect(fake.requests("/.well-known/openid-configuration").count == 2)
    }

    @Test("Network failures are network_error")
    func networkError() async {
        let fake = FakeNine()
        fake.state.withLock { $0.tokenNetworkError = URLError(.notConnectedToInternet) }
        let nine = fake.client()
        await expectNineError(.networkError) { try await nine.signIn() }
        #expect(!nine.isSignedIn)
    }

    @Test("The authorization endpoint keeps its own query")
    func endpointQuery() async throws {
        let fake = FakeNine()
        fake.state.withLock { $0.discovery["authorization_endpoint"] = .string("\(fake.issuer)/oauth/authorize?tenant=acme") }
        try await fake.client().signIn()
        #expect(fake.visits.first?.query["tenant"] == "acme")
        #expect(fake.visits.first?.query["response_type"] == "code")
    }

    @Test("Values with + and spaces are escaped in the authorization URL")
    func escaping() async throws {
        let fake = FakeNine()
        try await fake.client().signIn(loginHint: "jane+test@example.com")
        let url = try #require(fake.visits.first?.url.absoluteString)
        #expect(url.contains("login_hint=jane%2Btest%40example.com"))
        #expect(url.contains("scope=openid%20profile%20email%20offline_access"))
        #expect(fake.visits.first?.query["login_hint"] == "jane+test@example.com")
    }
}
