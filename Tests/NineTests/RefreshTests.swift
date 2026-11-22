import Foundation
import Testing
@testable import Nine

@Suite("Access tokens, refresh and rotation")
struct RefreshTests {
    private func signedIn(_ fake: FakeNine = FakeNine(), store: CredentialStore = MemoryCredentialStore()) async throws -> NineClient {
        let nine = fake.client(store: store)
        try await nine.signIn()
        return nine
    }

    @Test("A fresh access token is returned without a request")
    func fresh() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        let before = fake.requests.count
        let token = try await nine.accessToken()
        #expect(token == nine.tokens?.accessToken)
        #expect(fake.requests.count == before)
    }

    @Test("Within a minute of expiry the token is refreshed and the rotated refresh token saved")
    func rotation() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let nine = try await signedIn(fake, store: store)
        let first = try #require(nine.tokens)

        fake.clock.advance(3600 - 59)
        let token = try await nine.accessToken()

        let second = try #require(nine.tokens)
        #expect(token == second.accessToken)
        #expect(token != first.accessToken)
        #expect(second.refreshToken != first.refreshToken)
        let request = try #require(fake.requests("/oauth/token").last)
        #expect(request.form == ["grant_type": "refresh_token", "refresh_token": first.refreshToken!, "client_id": fake.clientId])
        // The new refresh token is what a new launch finds.
        let reloaded = fake.client(store: store)
        #expect(reloaded.tokens?.refreshToken == second.refreshToken)
        // The old one is spent: using it again fails at 9in.
        #expect(fake.state.current.refreshTokens[first.refreshToken!]?.used == true)
    }

    @Test("A refresh answer without a refresh token keeps the old one")
    func noRotation() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        let first = try #require(nine.tokens?.refreshToken)
        fake.state.withLock { $0.rotate = false }
        try await nine.refresh()
        #expect(nine.tokens?.refreshToken == first)
    }

    @Test("Concurrent accessToken() calls share one refresh")
    func singleFlight() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        fake.clock.advance(3600)
        fake.state.withLock { $0.tokenDelay = 200_000_000 }
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<25 { group.addTask { try await nine.accessToken() } }
            return try await group.reduce(into: [String]()) { $0.append($1) }
        }
        #expect(Set(tokens).count == 1)
        #expect(fake.requests("/oauth/token").filter { $0.form["grant_type"] == "refresh_token" }.count == 1)
        #expect(tokens.first == nine.tokens?.accessToken)
    }

    @Test("refresh() refreshes even a fresh token, and joins one in flight")
    func forced() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        let first = try #require(nine.tokens)
        fake.state.withLock { $0.tokenDelay = 100_000_000 }
        async let a = nine.refresh()
        async let b = nine.refresh()
        let (x, y) = try await (a, b)
        #expect(x == y)
        #expect(x.accessToken != first.accessToken)
        #expect(fake.requests("/oauth/token").filter { $0.form["grant_type"] == "refresh_token" }.count == 1)
    }

    @Test("A refused refresh token signs the user out (login_required)")
    func invalidGrant() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let nine = try await signedIn(fake, store: store)
        fake.clock.advance(3600)
        fake.state.withLock { $0.tokenFailures = [(400, ["error": "invalid_grant", "error_description": "refresh token is invalid, expired or revoked"])] }
        let error = await expectNineError(.loginRequired) { _ = try await nine.accessToken() }
        #expect(error?.message?.contains("revoked") == true)
        #expect(!nine.isSignedIn)
        #expect(nine.user == nil)
        #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)
        await expectNineError(.loginRequired) { _ = try await nine.accessToken() }
    }

    @Test("A network failure or a 5xx keeps the session")
    func transientFailures() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        fake.clock.advance(3600)
        fake.state.withLock { $0.tokenNetworkError = URLError(.timedOut) }
        await expectNineError(.networkError) { _ = try await nine.accessToken() }
        #expect(nine.isSignedIn)
        fake.state.withLock { $0.tokenNetworkError = nil; $0.tokenFailures = [(503, ["error": "temporarily_unavailable"])] }
        await expectNineError("temporarily_unavailable") { _ = try await nine.accessToken() }
        #expect(nine.isSignedIn)
        // It works again once 9in answers.
        _ = try await nine.accessToken()
        #expect(nine.isSignedIn)
    }

    @Test("The ID token from a refresh is verified; a bad one is ignored, the tokens are kept")
    func refreshIDToken() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        let firstID = try #require(nine.tokens?.idToken)

        fake.state.withLock { $0.email = "jane.new@example.com" }
        try await nine.refresh()
        #expect(nine.user?.email == "jane.new@example.com")
        let secondID = try #require(nine.tokens?.idToken)
        #expect(secondID != firstID)

        // Another user's ID token in a refresh answer is not taken.
        fake.state.withLock { $0.sub = "usr_other"; $0.email = "other@example.com" }
        let rotated = try await nine.refresh()
        #expect(nine.user?.sub == "usr_8k2")
        #expect(nine.user?.email == "jane.new@example.com")
        #expect(nine.tokens?.idToken == secondID)
        #expect(nine.tokens?.accessToken == rotated.accessToken)

        // No ID token in the answer: the previous one stays.
        fake.state.withLock { $0.sub = "usr_8k2"; $0.idTokenOnRefresh = false }
        try await nine.refresh()
        #expect(nine.tokens?.idToken == secondID)
    }

    @Test("Without a refresh token, a valid access token is still returned; an expired one signs out")
    func noRefreshToken() async throws {
        let fake = FakeNine()
        let nine = fake.client { $0.scopes = ["openid", "email"] }
        try await nine.signIn()
        #expect(nine.tokens?.refreshToken == nil)
        fake.clock.advance(3600 - 30)
        _ = try await nine.accessToken()
        await expectNineError(.loginRequired) { try await nine.refresh() }
        #expect(nine.isSignedIn)
        fake.clock.advance(31)
        await expectNineError(.loginRequired) { _ = try await nine.accessToken() }
        #expect(!nine.isSignedIn)
    }

    @Test("Signed out: login_required")
    func signedOut() async {
        let nine = FakeNine().client()
        await expectNineError(.loginRequired) { _ = try await nine.accessToken() }
        await expectNineError(.loginRequired) { try await nine.refresh() }
    }

    @Test("A sign-out during a refresh wins: the refreshed tokens are thrown away")
    func signOutDuringRefresh() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let nine = try await signedIn(fake, store: store)
        fake.clock.advance(3600)
        fake.state.withLock { $0.tokenDelay = 300_000_000 }
        let pending = Task { try await nine.accessToken() }
        try await Task.sleep(nanoseconds: 50_000_000)
        try await nine.signOut(endSession: false)
        await expectNineError(.loginRequired) { _ = try await pending.value }
        #expect(!nine.isSignedIn)
        #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)
    }

    @Test("A new sign-in during a refresh wins over the old session's refresh")
    func signInDuringRefresh() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        fake.clock.advance(3600)
        fake.state.withLock { $0.tokenDelay = 300_000_000 }
        let pending = Task { try await nine.accessToken() }
        try await Task.sleep(nanoseconds: 50_000_000)
        fake.state.withLock { $0.tokenDelay = 0; $0.email = "second@example.com" }
        try await nine.signIn()
        let afterSignIn = try #require(nine.tokens)
        let token = try await pending.value
        #expect(token == afterSignIn.accessToken)
        #expect(nine.tokens == afterSignIn)
        #expect(nine.user?.email == "second@example.com")
    }

    @Test("authorize(_:) adds the bearer token")
    func authorize() async throws {
        let nine = try await signedIn()
        let request = try await nine.authorize(URLRequest(url: URL(string: "https://api.acme.com/orders")!))
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(nine.tokens!.accessToken)")
    }

    @Test("userInfo() calls the endpoint with the access token and checks sub")
    func userInfo() async throws {
        let fake = FakeNine()
        let nine = try await signedIn(fake)
        let info = try await nine.userInfo()
        #expect(info.sub == "usr_8k2")
        #expect(info.email == "jane@example.com")
        #expect(fake.requests("/oauth/userinfo").last?.headers["Authorization"] == "Bearer \(nine.tokens!.accessToken)")

        fake.state.withLock { $0.userinfoSub = "usr_other" }
        await expectNineError(.invalidResponse) { _ = try await nine.userInfo() }

        fake.state.withLock { $0.userinfoSub = nil; $0.accessTokens = [] }
        let error = await expectNineError(.invalidToken) { _ = try await nine.userInfo() }
        #expect(error?.status == 401)
    }
}
