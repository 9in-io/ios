import Foundation
import Nine

/// Your tenant and a Native / Mobile application (Applications → Create application →
/// Native / Mobile in the 9in console). Add the redirect URI to its allowed callback URLs, and
/// the post-logout one to its allowed logout URLs.
///
/// Launch arguments override these (`-NineIssuer https://… -NineClientId app_…`), which is how
/// the UI tests point the app at their mock issuer.
enum Config {
    static let issuer = value("NineIssuer") ?? "https://acme.9in.io"
    static let clientId = value("NineClientId") ?? "YOUR_CLIENT_ID"
    static let redirectURI = value("NineRedirectURI") ?? "io.ninein.example:/callback"
    static let postLogoutRedirectURI = value("NinePostLogoutRedirectURI")
    static let audience = value("NineAudience")

    static var configuration: NineClient.Configuration {
        NineClient.Configuration(
            issuer: issuer,
            clientId: clientId,
            redirectURI: redirectURI,
            audience: audience,
            postLogoutRedirectURI: postLogoutRedirectURI,
            prefersEphemeralWebBrowserSession: UserDefaults.standard.bool(forKey: "NineEphemeral")
        )
    }

    /// The Keychain, under a service of its own when the UI tests ask for one.
    static var store: CredentialStore {
        KeychainCredentialStore(service: value("NineKeychainService") ?? "io.9in.nine")
    }

    private static func value(_ key: String) -> String? {
        UserDefaults.standard.string(forKey: key).flatMap { $0.isEmpty ? nil : $0 }
    }
}
