import Foundation
import Testing
@testable import Nine

@Suite("Sign-out, revocation and the logout URL")
struct SignOutTests {
    @Test("Signs out: forgets the tokens, revokes the refresh token, ends the 9in session in the browser")
    func signOut() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let nine = fake.client(store: store)
        try await nine.signIn()
        let tokens = try #require(nine.tokens)

        try await nine.signOut()

        #expect(!nine.isSignedIn)
        #expect(nine.user == nil)
        #expect(nine.tokens == nil)
        #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)
        let revoke = try #require(fake.requests("/oauth/revoke").first)
        #expect(revoke.form == ["token": tokens.refreshToken!, "token_type_hint": "refresh_token", "client_id": fake.clientId])
        let visit = try #require(fake.visits.last)
        #expect(visit.url.path == "/oauth/logout")
        #expect(visit.query["client_id"] == fake.clientId)
        #expect(visit.query["id_token_hint"] == tokens.idToken)
        #expect(visit.query["post_logout_redirect_uri"] == nil) // none configured: never send an unregistered one
        #expect(visit.query["state"] != nil)
        #expect(visit.ephemeral == false)
        await expectNineError(.loginRequired) { _ = try await nine.accessToken() }
    }

    @Test("With a post-logout redirect URI, the browser comes back by itself")
    func postLogoutRedirect() async throws {
        let fake = FakeNine()
        let nine = fake.client { $0.postLogoutRedirectURI = "com.example.app:/signed-out" }
        try await nine.signIn()
        try await nine.signOut()
        let visit = try #require(fake.visits.last)
        #expect(visit.query["post_logout_redirect_uri"] == "com.example.app:/signed-out")
        #expect(visit.callbackURL.absoluteString == "com.example.app:/signed-out")
    }

    @Test("endSession: false skips the browser; so does a private (ephemeral) sign-in")
    func noBrowser() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signIn()
        try await nine.signOut(endSession: false)
        #expect(fake.visits.count == 1)
        #expect(fake.requests("/oauth/revoke").count == 1)

        try await nine.signIn(ephemeral: true)
        try await nine.signOut()
        #expect(fake.visits.count == 2)
        #expect(fake.requests("/oauth/revoke").count == 2)
    }

    @Test("Revocation failures and a failing browser step still sign the user out")
    func failures() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signIn()
        fake.state.withLock { $0.revokeStatus = 500; $0.browserError = NineError(.browserFailed, "no window") }
        await expectNineError(.browserFailed) { try await nine.signOut() }
        #expect(!nine.isSignedIn)
        #expect(fake.requests("/oauth/revoke").count == 1)

        // A failing revocation alone is not an error.
        fake.state.withLock { $0.browserError = nil }
        try await nine.signIn()
        try await nine.signOut()
        #expect(fake.requests("/oauth/revoke").count == 2)
        #expect(!nine.isSignedIn)
    }

    @Test("Without a refresh token, the access token is revoked")
    func revokeAccessToken() async throws {
        let fake = FakeNine()
        let nine = fake.client { $0.scopes = ["openid"] }
        try await nine.signIn()
        let access = try #require(nine.tokens?.accessToken)
        try await nine.signOut(endSession: false)
        #expect(fake.requests("/oauth/revoke").first?.form["token"] == access)
        #expect(fake.requests("/oauth/revoke").first?.form["token_type_hint"] == "access_token")
    }

    @Test("Signing out when nobody is signed in does nothing")
    func nobody() async throws {
        let fake = FakeNine()
        try await fake.client().signOut()
        #expect(fake.requests("/oauth/revoke").isEmpty)
        #expect(fake.visits.isEmpty)
    }

    @Test("logoutURL builds the RP-initiated logout URL")
    func logoutURL() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        let anonymous = try await nine.logoutURL()
        #expect(anonymous.absoluteString == "\(fake.issuer)/oauth/logout?client_id=\(fake.clientId)")
        try await nine.signIn()
        let url = try await nine.logoutURL(postLogoutRedirectURI: "com.example.app:/bye", state: "s1")
        let query = Dictionary(uniqueKeysWithValues: URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
        #expect(url.absoluteString.hasPrefix("\(fake.issuer)/oauth/logout?"))
        #expect(query == ["client_id": fake.clientId, "id_token_hint": nine.tokens!.idToken!, "post_logout_redirect_uri": "com.example.app:/bye", "state": "s1"])
        await expectNineError(.invalidOptions) { _ = try await nine.logoutURL(postLogoutRedirectURI: "nope") }

        // Without end_session_endpoint in discovery: <issuer>/oauth/logout.
        let bare = FakeNine()
        bare.state.withLock { $0.discovery["end_session_endpoint"] = .null }
        #expect(try await bare.client().logoutURL().absoluteString == "\(bare.issuer)/oauth/logout?client_id=\(bare.clientId)")
    }
}
