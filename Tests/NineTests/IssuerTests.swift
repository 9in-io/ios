import Foundation
import Testing
@testable import Nine

@Suite("Issuers must use https")
struct IssuerTests {
    @Test("https issuers are accepted and a trailing slash dropped", arguments: [
        ("https://acme.9in.io", "https://acme.9in.io"),
        ("https://acme.9in.io/", "https://acme.9in.io"),
        ("https://login.acme.com/tenant", "https://login.acme.com/tenant"),
        ("HTTPS://Acme.9in.IO/", "https://acme.9in.io"),
        ("https://Login.acme.com/Tenant", "https://login.acme.com/Tenant"),
    ])
    func https(input: String, expected: String) throws {
        #expect(try Issuer.normalize(input, allowInsecure: false) == expected)
    }

    @Test("Plain http is accepted for localhost and loopback", arguments: [
        "http://localhost:8787", "http://auth.localhost", "http://127.0.0.1:8897", "http://127.1.2.3", "http://[::1]:8080",
    ])
    func localHTTP(issuer: String) throws {
        #expect(try Issuer.normalize(issuer, allowInsecure: false) == issuer)
    }

    @Test("Other http issuers are refused unless allowed", arguments: [
        "http://acme.9in.io", "http://auth:8897", "http://127.0.0.1.evil.com", "http://localhost.evil.com", "http://10.0.0.1", "ftp://acme.9in.io",
    ])
    func insecure(issuer: String) async throws {
        await expectNineError(.insecureIssuer) { _ = try Issuer.normalize(issuer, allowInsecure: false) }
    }

    @Test("allowInsecureIssuer lets http through")
    func allowInsecure() throws {
        #expect(try Issuer.normalize("http://auth:8897/", allowInsecure: true) == "http://auth:8897")
    }

    @Test("Queries, fragments, credentials and non-URLs are refused", arguments: [
        "https://acme.9in.io?x=1", "https://acme.9in.io#top", "https://user:pass@acme.9in.io", "https://user@acme.9in.io", "acme.9in.io", "", "not a url", "https://",
    ])
    func invalid(issuer: String) async throws {
        await expectNineError(.invalidIssuer) { _ = try Issuer.normalize(issuer, allowInsecure: false) }
    }

    @Test("A client with an http issuer throws insecure_issuer from every call")
    func clientWithInsecureIssuer() async throws {
        let nine = NineClient(issuer: "http://acme.9in.io", clientId: "app", redirectURI: "com.acme.app:/callback")
        #expect(nine.isSignedIn == false)
        #expect(nine.user == nil)
        await expectNineError(.insecureIssuer) { try await nine.signIn() }
        await expectNineError(.insecureIssuer) { _ = try await nine.accessToken() }
        await expectNineError(.insecureIssuer) { try await nine.signOut() }
        await expectNineError(.insecureIssuer) { _ = try await nine.userInfo() }
    }

    @Test("Wrong client settings throw invalid_options")
    func invalidOptions() async throws {
        let cases: [NineClient.Configuration] = [
            .init(issuer: "https://acme.9in.io", clientId: "", redirectURI: "com.acme.app:/callback"),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "not a uri"),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "com.acme.app:/callback?x=1"),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "http://app.acme.com/callback"),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "com.acme.app:/callback", scopes: ["profile", "email"]),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "com.acme.app:/callback", postLogoutRedirectURI: "nope"),
            .init(issuer: "https://acme.9in.io", clientId: "app", redirectURI: "com.acme.app:/callback", postLogoutRedirectURI: "http://app.acme.com/bye"),
        ]
        for configuration in cases {
            let nine = NineClient(configuration: configuration, store: MemoryCredentialStore())
            await expectNineError(.invalidOptions) { try await nine.signIn() }
        }
    }

    @Test("Scopes can be given as one space-separated string")
    func scopeString() throws {
        let resolved = try ResolvedConfiguration(.init(issuer: "https://acme.9in.io/", clientId: "app", redirectURI: "com.acme.app:/callback", scopes: ["openid email", "offline_access"]))
        #expect(resolved.scope == "openid email offline_access")
        #expect(resolved.issuer == "https://acme.9in.io")
        #expect(resolved.storeKey == "https://acme.9in.io app")
    }
}
