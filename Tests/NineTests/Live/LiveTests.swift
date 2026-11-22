import Foundation
import Testing
@testable import Nine

/// The SDK against live 9in: the sdk-e2e tenant's sandbox and its public SPA client, through
/// 9in's real hosted pages (driven over HTTP through the `Browser` seam). Opt-in:
///
///     NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e swift test --filter Live
///
/// The sandbox accepts any password and creates the user on first sign-in; the user is deleted
/// at the end through the Management API (confidential E2E Server client).
///
/// Token values never appear in expectations, so a failure can't print one.
@Suite("Live e2e against 9in", .enabled(if: Live.enabled), .serialized)
struct LiveTests {
    private func client(_ browser: Browser, store: CredentialStore, transport: HTTPTransport = URLSessionTransport(), now: @escaping @Sendable () -> Date = { Date() }) throws -> NineClient {
        let configuration = NineClient.Configuration(
            issuer: try Live.env("SANDBOX_ISSUER"),
            clientId: try Live.env("SPA_CLIENT_ID"),
            redirectURI: try Live.env("SPA_REDIRECT_URI"),
            scopes: ["openid", "profile", "email", "offline_access", "read:things"],
            audience: try Live.env("API_AUDIENCE")
        )
        return NineClient(configuration: configuration, store: store, browser: browser, transport: transport, now: now)
    }

    @Test("Discovery, sign-in, userinfo, refresh rotation, single-flight refresh, revoke, logout")
    func scenario() async throws {
        var failure: Error?
        do {
            try await signInAndUse()
            try await refusedCallbacks()
        } catch {
            failure = error
        }
        let deleted = try await LiveAPI.deleteUser(email: Live.email)
        #expect(deleted, "the test user existed and was deleted")
        if let failure { throw failure }
    }

    private func signInAndUse() async throws {
        let issuer = try Live.env("SANDBOX_ISSUER")
        let audience = try Live.env("API_AUDIENCE")

        // Discovery: the real document passes the SDK's checks (issuer, https endpoints, RFC 9207).
        let provider = Provider(issuer: issuer, http: HTTPClient(transport: URLSessionTransport()), allowInsecure: false, now: { Date() })
        let discovery = try await provider.configuration()
        #expect(discovery.issParameterSupported)
        #expect(discovery.endSessionEndpoint != nil && discovery.revocationEndpoint != nil && discovery.userinfoEndpoint != nil)

        let store = KeychainCredentialStore(service: "io.9in.nine.e2e.\(Live.run)")
        let browser = HostedPageBrowser(identifier: Live.email, password: "any-password-\(Live.run)")
        let transport = CountingTransport()
        let nine = try client(browser, store: store, transport: transport)
        defer { try? store.delete("\(issuer) \(nine.configuration.clientId)") }

        // Sign-in through the hosted page: PKCE, state, nonce, iss, ID token signature and claims.
        let user = try await nine.signIn()
        #expect(browser.formsSubmitted.current == 1)
        #expect(user.email == Live.email)
        #expect(user.sub.hasPrefix("usr_"))
        #expect(user.amr.contains("pwd"))
        let signedIn = nine.isSignedIn
        #expect(signedIn)
        let first = try #require(nine.tokens)
        let hasRefreshToken = first.refreshToken != nil
        #expect(hasRefreshToken)
        #expect(first.scope?.split(separator: " ").contains("read:things") == true)
        #expect(first.expiresAt > Date().addingTimeInterval(60))

        // The access token is a JWT access token for the API.
        let access = try #require(JWT(first.accessToken))
        #expect(access.header["typ"]?.stringValue?.lowercased() == "at+jwt")
        let audienceMatches = access.claims["aud"]?.stringValue == audience || access.claims["aud"]?.arrayValue?.contains(.string(audience)) == true
        #expect(audienceMatches)
        #expect(access.claims["sub"]?.stringValue == user.sub)
        let clientClaim = access.claims["client_id"]?.stringValue == nine.configuration.clientId
        #expect(clientClaim)

        // Single sign-on: a second sign-in in the same browser doesn't ask again.
        try await nine.signIn()
        #expect(browser.formsSubmitted.current == 1)

        // Userinfo.
        let info = try await nine.userInfo()
        #expect(info.sub == user.sub)
        #expect(info.email == Live.email)

        // A fresh token comes from memory; the Keychain has the session for the next launch.
        let before = transport.count("POST /oauth/token")
        let token = try await nine.accessToken()
        let sameToken = token == nine.tokens?.accessToken
        #expect(sameToken)
        #expect(transport.count("POST /oauth/token") == before)
        let relaunched = try client(browser, store: store).user == nine.user
        #expect(relaunched)

        // Refresh rotates the refresh token, and the new one is saved.
        let current = try #require(nine.tokens)
        let refreshed = try await nine.refresh()
        let rotated = refreshed.refreshToken != nil && refreshed.refreshToken != current.refreshToken
        let newAccess = refreshed.accessToken != current.accessToken
        #expect(rotated)
        #expect(newAccess)
        let saved = try client(browser, store: store).tokens?.refreshToken == refreshed.refreshToken
        #expect(saved)
        // The ID token from the refresh was verified and is for the same user.
        let sameUser = nine.user?.sub == user.sub
        #expect(sameUser)

        // 9in's 30-second grace: the old refresh token used again returns the same new one.
        let tokenEndpoint = discovery.tokenEndpoint
        let (graceStatus, grace) = try await LiveAPI.post(tokenEndpoint, ["grant_type": "refresh_token", "refresh_token": current.refreshToken!, "client_id": nine.configuration.clientId])
        #expect(graceStatus == 200)
        let sameRotation = grace["refresh_token"]?.stringValue == refreshed.refreshToken
        #expect(sameRotation)

        // Concurrent accessToken() calls with an expired token share one refresh. A client whose
        // clock runs 59 minutes ahead sees the token expiring.
        let ahead = CountingTransport()
        let later = try client(browser, store: store, transport: ahead, now: { Date().addingTimeInterval(3540) })
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<10 { group.addTask { try await later.accessToken() } }
            return try await group.reduce(into: Set<String>()) { $0.insert($1) }
        }
        #expect(tokens.count == 1)
        #expect(ahead.count("POST /oauth/token refresh_token") == 1)
        let laterRotated = later.tokens?.refreshToken != refreshed.refreshToken
        #expect(laterRotated)

        // The logout URL.
        let logout = try await later.logoutURL(postLogoutRedirectURI: nil, state: "s1")
        let logoutEndpoint = logout.absoluteString.hasPrefix("\(issuer)/oauth/logout?")
        #expect(logoutEndpoint)
        let query = Dictionary(uniqueKeysWithValues: URLComponents(url: logout, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value ?? "") })
        let hint = query["id_token_hint"] == later.tokens?.idToken
        #expect(hint)
        let clientMatches = query["client_id"] == later.configuration.clientId
        #expect(clientMatches)

        // Sign-out: revokes the refresh token and ends the 9in session in the browser.
        let lastRefresh = try #require(later.tokens?.refreshToken)
        try await later.signOut()
        let laterSignedOut = !later.isSignedIn
        #expect(laterSignedOut)
        #expect(try store.read("\(issuer) \(later.configuration.clientId)") == nil)
        // The browser stayed on 9in's "You've signed out" page (no post-logout redirect URI).
        let signedOutPage = browser.lastPage.current.map { $0.status == 200 && $0.text.contains("signed out") } ?? false
        #expect(signedOutPage)
        let (revokedStatus, revoked) = try await LiveAPI.post(tokenEndpoint, ["grant_type": "refresh_token", "refresh_token": lastRefresh, "client_id": later.configuration.clientId])
        #expect(revokedStatus == 400)
        #expect(revoked["error"]?.stringValue == "invalid_grant")
        // The 9in session ended: signing in again asks for the password.
        try await later.signIn()
        #expect(browser.formsSubmitted.current == 2)

        // A refresh token revoked behind the app's back: the next refresh signs the user out.
        let (revokeStatus, _) = try await LiveAPI.post(discovery.revocationEndpoint!, ["token": later.tokens!.refreshToken!, "token_type_hint": "refresh_token", "client_id": later.configuration.clientId])
        #expect(revokeStatus == 200)
        await expectNineError(.loginRequired) { try await later.refresh() }
        let signedOut = !later.isSignedIn && later.user == nil && later.tokens == nil
        #expect(signedOut)
        await expectNineError(.loginRequired) { _ = try await later.accessToken() }
    }

    /// Callbacks changed on the way back are refused before the code is spent; the untouched
    /// callback then still signs in.
    private func refusedCallbacks() async throws {
        let issuer = try Live.env("SANDBOX_ISSUER")
        let browser = HostedPageBrowser(identifier: Live.email, password: "x")
        let nine = try client(browser, store: MemoryCredentialStore())
        let cases: [(NineError.Code, @Sendable (URL) -> URL)] = [
            (.invalidState, { with($0, ["state": "forged"]) }),
            (.invalidIssuer, { with($0, ["iss": "https://evil.example"]) }),
            (.invalidIssuer, { with($0, ["iss": nil]) }),
            (.accessDenied, { with($0, ["code": nil, "error": "access_denied"]) }),
            (.invalidGrant, { with($0, ["code": "forged-code"]) }),
        ]
        for (code, change) in cases {
            browser.tamper.withLock { $0 = change }
            await expectNineError(code) { try await nine.signIn() }
            let refused = !nine.isSignedIn
            #expect(refused)
        }
        browser.tamper.withLock { $0 = nil }
        let user = try await nine.signIn()
        #expect(user.email == Live.email)
        #expect(Issuer.same(user["iss"]?.stringValue ?? "", issuer))
    }
}
