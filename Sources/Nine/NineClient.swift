import Combine
import Foundation
#if canImport(Observation)
import Observation
#endif

/// Signs users in to your app with 9in's hosted login: authorization code flow with PKCE in the
/// system browser, tokens kept in the Keychain and refreshed (with rotation) when needed.
///
/// ```swift
/// let nine = NineClient(issuer: "https://acme.9in.io", clientId: "app_…", redirectURI: "com.acme.app:/callback")
/// let user = try await nine.signIn()
/// let token = try await nine.accessToken()   // refreshed when it is about to expire
/// try await nine.signOut()
/// ```
///
/// Create one client for your app and share it. It is safe to use from any thread or task;
/// concurrent `accessToken()` calls share one refresh. For SwiftUI it is an `ObservableObject`
/// (and `Observable` on iOS 17+ / macOS 14+): `user` and `isSignedIn` update on the main actor.
public final class NineClient: ObservableObject, @unchecked Sendable {
    // @unchecked Sendable: the token state lives in the `AuthCore` actor; `snapshot` is behind a
    // lock; `objectWillChange` and the observation registrar are only used on the main actor.

    /// The configuration this client was created with.
    public let configuration: Configuration
    public let objectWillChange = ObservableObjectPublisher()

    private let core: Result<AuthCore, NineError>
    private let snapshot: Locked<Snapshot>
    private let registrar: Any?

    private struct Snapshot {
        var session: StoredSession?
        var version: UInt64
    }

    /// - Parameters:
    ///   - issuer: your tenant's issuer, e.g. `https://acme.9in.io` or your custom domain.
    ///   - clientId: the client ID of a **Native / Mobile** application.
    ///   - redirectURI: one of its allowed callback URLs, e.g. `com.acme.app:/callback`.
    ///   - scopes: default `openid profile email offline_access`.
    ///   - audience: an API identifier, to get access tokens for that API.
    ///
    /// A wrong configuration (an `http://` issuer, a redirect URI that isn't a URL) doesn't stop
    /// the app: every call throws the `NineError` that says what is wrong.
    public convenience init(issuer: String, clientId: String, redirectURI: String, scopes: [String] = NineClient.defaultScopes, audience: String? = nil) {
        self.init(configuration: Configuration(issuer: issuer, clientId: clientId, redirectURI: redirectURI, scopes: scopes, audience: audience))
    }

    /// - Parameters:
    ///   - store: where tokens are kept between launches (default: the Keychain).
    ///   - browser: shows the hosted pages (default: `ASWebAuthenticationSession`).
    ///   - transport: sends HTTP requests (default: an ephemeral `URLSession`, 10 s timeout).
    public convenience init(configuration: Configuration, store: CredentialStore = KeychainCredentialStore(), browser: Browser = SystemBrowser(), transport: HTTPTransport = URLSessionTransport()) {
        self.init(configuration: configuration, store: store, browser: browser, transport: transport, now: { Date() })
    }

    init(configuration: Configuration, store: CredentialStore, browser: Browser, transport: HTTPTransport, now: @escaping @Sendable () -> Date) {
        self.configuration = configuration
        let relay = ChangeRelay()
        do {
            let resolved = try ResolvedConfiguration(configuration)
            var initial: StoredSession?
            var needsLoad = false
            do {
                initial = try AuthCore.load(store, key: resolved.storeKey)
            } catch {
                needsLoad = true // e.g. the Keychain is locked until the first unlock: try again later
            }
            core = .success(AuthCore(config: resolved, store: store, browser: browser, transport: transport, now: now, relay: relay, initial: initial, needsLoad: needsLoad))
            snapshot = Locked(Snapshot(session: initial, version: 0))
        } catch {
            core = .failure(error as? NineError ?? NineError(.invalidOptions, String(describing: error)))
            snapshot = Locked(Snapshot(session: nil, version: 0))
        }
        #if canImport(Observation)
        if #available(iOS 17.0, macOS 14.0, macCatalyst 17.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *) {
            registrar = ObservationRegistrar()
        } else {
            registrar = nil
        }
        #else
        registrar = nil
        #endif
        relay.attach(self)
    }

    private func engine() throws -> AuthCore {
        try core.get()
    }

    // MARK: State

    /// The signed-in user (the claims of the verified ID token), or nil.
    public var user: NineUser? {
        access(\.user)
        return snapshot.withLock { $0.session.map { NineUser(claims: $0.claims) } }
    }

    /// True while there is a session: tokens that are valid or can be refreshed. It turns false
    /// on sign-out, and when 9in refuses the refresh token (the session ended).
    public var isSignedIn: Bool {
        access(\.isSignedIn)
        return snapshot.withLock { $0.session != nil }
    }

    /// The current tokens, possibly expired. Use `accessToken()` to get a valid access token.
    public var tokens: TokenSet? {
        access(\.tokens)
        return snapshot.withLock { $0.session?.tokens }
    }

    // MARK: Sign-in

    /// Opens 9in's hosted login in the system browser and signs the user in.
    ///
    /// - Parameters:
    ///   - loginHint: prefills the identifier (an email address, a phone number…).
    ///   - prompt: `.login` to ask for the password again even with a 9in session, `.selectAccount`, `.consent`.
    ///   - maxAge: seconds; ask the user to sign in again if their last sign-in is older.
    ///   - parameters: extra authorization parameters (they never replace state, nonce or PKCE).
    ///   - ephemeral: overrides `prefersEphemeralWebBrowserSession` for this sign-in.
    /// - Returns: the signed-in user.
    /// - Throws: `NineError`: `.canceled` when the user closes the sheet, `.accessDenied`, …
    @discardableResult
    public func signIn(loginHint: String? = nil, prompt: Prompt? = nil, maxAge: Int? = nil, parameters: [String: String] = [:], ephemeral: Bool? = nil) async throws -> NineUser {
        try await engine().signIn(prompt: prompt?.rawValue, loginHint: loginHint, maxAge: maxAge, parameters: parameters, ephemeral: ephemeral)
    }

    /// Opens the sign-up form (`prompt=create`) and signs the new user in.
    @discardableResult
    public func signUp(loginHint: String? = nil, parameters: [String: String] = [:], ephemeral: Bool? = nil) async throws -> NineUser {
        try await signIn(loginHint: loginHint, prompt: .create, parameters: parameters, ephemeral: ephemeral)
    }

    // MARK: Tokens

    /// A valid access token, refreshed first when it expires within a minute. 9in rotates the
    /// refresh token on every refresh; the new one is saved. Concurrent calls share one refresh.
    ///
    /// - Throws: `NineError(.loginRequired)` when nobody is signed in or the session ended
    ///   (the user is then signed out); `.networkError` when 9in can't be reached (the tokens are kept).
    public func accessToken() async throws -> String {
        try await engine().validTokens(forceRefresh: false).accessToken
    }

    /// Refreshes the tokens now, for example after your API refused the access token.
    @discardableResult
    public func refresh() async throws -> TokenSet {
        try await engine().validTokens(forceRefresh: true)
    }

    /// `request` with `Authorization: Bearer <access token>`.
    public func authorize(_ request: URLRequest) async throws -> URLRequest {
        var request = request
        request.setValue("Bearer \(try await accessToken())", forHTTPHeaderField: "Authorization")
        return request
    }

    /// The user's current profile from the userinfo endpoint (it doesn't change `user`).
    public func userInfo() async throws -> NineUser {
        try await engine().userInfo()
    }

    // MARK: Sign-out

    /// Signs the user out: forgets the tokens, revokes the refresh token at 9in, and (unless
    /// `endSession` is false) ends the 9in session in the system browser, so the next sign-in asks
    /// for the password again. With a `postLogoutRedirectURI` the browser closes by itself;
    /// without one, the user closes 9in's "You're signed out" page.
    ///
    /// The user is signed out in the app even if the browser step is canceled or fails.
    public func signOut(endSession: Bool = true) async throws {
        try await engine().signOut(endSession: endSession)
    }

    /// The URL that ends the 9in session (RP-initiated logout), with the current ID token as
    /// `id_token_hint`. `postLogoutRedirectURI` defaults to the configured one.
    public func logoutURL(postLogoutRedirectURI: String? = nil, state: String? = nil) async throws -> URL {
        let redirect = try postLogoutRedirectURI.map { value -> URL in
            guard let url = URL(string: value), url.scheme != nil else { throw NineError(.invalidOptions, "postLogoutRedirectURI is not a URL: \(value)") }
            return url
        }
        return try await engine().logoutURL(postLogoutRedirectURI: redirect, state: state)
    }

    // MARK: Observation

    @MainActor
    func apply(_ session: StoredSession?, version: UInt64) {
        guard version > snapshot.withLock({ $0.version }) else { return }
        objectWillChange.send()
        willSet()
        snapshot.withLock { $0 = Snapshot(session: session, version: version) }
        didSet()
    }

    private func access<Value>(_ keyPath: KeyPath<NineClient, Value>) {
        #if canImport(Observation)
        if #available(iOS 17.0, macOS 14.0, macCatalyst 17.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *), let registrar = registrar as? ObservationRegistrar {
            registrar.access(self, keyPath: keyPath)
        }
        #endif
    }

    private func willSet() {
        #if canImport(Observation)
        if #available(iOS 17.0, macOS 14.0, macCatalyst 17.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *), let registrar = registrar as? ObservationRegistrar {
            registrar.willSet(self, keyPath: \.user)
            registrar.willSet(self, keyPath: \.isSignedIn)
            registrar.willSet(self, keyPath: \.tokens)
        }
        #endif
    }

    private func didSet() {
        #if canImport(Observation)
        if #available(iOS 17.0, macOS 14.0, macCatalyst 17.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *), let registrar = registrar as? ObservationRegistrar {
            registrar.didSet(self, keyPath: \.user)
            registrar.didSet(self, keyPath: \.isSignedIn)
            registrar.didSet(self, keyPath: \.tokens)
        }
        #endif
    }
}

extension NineClient: CustomReflectable {
    /// `dump(nine)` and debuggers show the configuration and the user, never tokens.
    public var customMirror: Mirror {
        Mirror(self, children: ["configuration": configuration, "isSignedIn": isSignedIn, "user": user?.sub as Any], displayStyle: .class)
    }
}

#if canImport(Observation)
@available(iOS 17.0, macOS 14.0, macCatalyst 17.0, tvOS 17.0, watchOS 10.0, visionOS 1.0, *)
extension NineClient: Observable {}
#endif
