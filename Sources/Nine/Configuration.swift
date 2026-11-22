import Foundation

extension NineClient {
    /// How a `NineClient` talks to your tenant.
    public struct Configuration: Sendable, Hashable {
        /// Your tenant's issuer, e.g. `https://acme.9in.io` or your custom domain.
        public var issuer: String
        /// The client ID of a **Native / Mobile** application in the 9in console.
        public var clientId: String
        /// Where 9in sends the browser back to, e.g. `com.acme.app:/callback`. Must be one of the
        /// application's allowed callback URLs.
        public var redirectURI: String
        /// Default `openid profile email offline_access` (`offline_access` gives a refresh token).
        public var scopes: [String]
        /// An API identifier, to get access tokens for that API.
        public var audience: String?
        /// Where 9in sends the browser after sign-out. Must be one of the application's allowed
        /// logout URLs; without one, 9in shows its "You're signed out" page.
        public var postLogoutRedirectURI: String?
        /// Language of the hosted pages (`ui_locales`), e.g. `de`.
        public var locale: String?
        /// Use a private browser session that shares no cookies with Safari: no single sign-on,
        /// and no "wants to use … to sign in" prompt. Default false.
        public var prefersEphemeralWebBrowserSession: Bool
        /// Accept a plain-http issuer other than localhost (development only).
        public var allowInsecureIssuer: Bool
        /// Seconds of clock difference tolerated when checking ID token times. Default 60.
        public var clockSkew: TimeInterval

        public init(
            issuer: String,
            clientId: String,
            redirectURI: String,
            scopes: [String] = NineClient.defaultScopes,
            audience: String? = nil,
            postLogoutRedirectURI: String? = nil,
            locale: String? = nil,
            prefersEphemeralWebBrowserSession: Bool = false,
            allowInsecureIssuer: Bool = false,
            clockSkew: TimeInterval = 60
        ) {
            self.issuer = issuer
            self.clientId = clientId
            self.redirectURI = redirectURI
            self.scopes = scopes
            self.audience = audience
            self.postLogoutRedirectURI = postLogoutRedirectURI
            self.locale = locale
            self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            self.allowInsecureIssuer = allowInsecureIssuer
            self.clockSkew = clockSkew
        }
    }

    /// `openid profile email offline_access`.
    public static let defaultScopes = ["openid", "profile", "email", "offline_access"]

    /// The `prompt` of a sign-in.
    public struct Prompt: RawRepresentable, Hashable, Sendable {
        public let rawValue: String
        public init(rawValue: String) { self.rawValue = rawValue }

        /// Ask the user to sign in again, even with a 9in session.
        public static let login = Prompt(rawValue: "login")
        /// Ask for consent again.
        public static let consent = Prompt(rawValue: "consent")
        /// Let the user pick an account.
        public static let selectAccount = Prompt(rawValue: "select_account")
        /// Open the sign-up form (what `signUp()` sends).
        public static let create = Prompt(rawValue: "create")
    }
}

/// A configuration checked once: the issuer normalised, the URLs parsed.
struct ResolvedConfiguration: Sendable {
    let issuer: String
    let clientId: String
    let redirectURI: URL
    let scope: String
    let audience: String?
    let postLogoutRedirectURI: URL?
    let locale: String?
    let ephemeral: Bool
    let allowInsecureIssuer: Bool
    let clockSkew: TimeInterval
    /// Where the tokens are saved in the credential store.
    let storeKey: String

    init(_ configuration: NineClient.Configuration) throws {
        issuer = try Issuer.normalize(configuration.issuer, allowInsecure: configuration.allowInsecureIssuer)
        guard !configuration.clientId.isEmpty else { throw NineError(.invalidOptions, "clientId is required") }
        clientId = configuration.clientId
        guard let redirect = URL(string: configuration.redirectURI), redirect.scheme != nil else {
            throw NineError(.invalidOptions, "redirectURI is not a URL: \(configuration.redirectURI)")
        }
        if redirect.query != nil || redirect.fragment != nil {
            throw NineError(.invalidOptions, "redirectURI has no query or fragment")
        }
        _ = try CallbackMatch(redirect)
        redirectURI = redirect
        let scopes = configuration.scopes.flatMap { $0.split(separator: " ").map(String.init) }
        guard scopes.contains("openid") else { throw NineError(.invalidOptions, "scopes must include openid") }
        scope = scopes.joined(separator: " ")
        audience = configuration.audience
        if let logout = configuration.postLogoutRedirectURI {
            guard let url = URL(string: logout), url.scheme != nil else {
                throw NineError(.invalidOptions, "postLogoutRedirectURI is not a URL: \(logout)")
            }
            postLogoutRedirectURI = url
        } else {
            postLogoutRedirectURI = nil
        }
        locale = configuration.locale
        ephemeral = configuration.prefersEphemeralWebBrowserSession
        allowInsecureIssuer = configuration.allowInsecureIssuer
        clockSkew = max(0, configuration.clockSkew)
        storeKey = "\(issuer) \(clientId)"
    }
}
