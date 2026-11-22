import Foundation

/// Every failure in this package is a `NineError`: a `code` (the same codes as the other 9in SDKs
/// and OAuth's own, such as `login_required`, `invalid_state` or `access_denied`), a readable
/// `message`, and the HTTP `status` when 9in answered with an error.
///
/// ```swift
/// do {
///     try await nine.signIn()
/// } catch let error as NineError where error.code == .canceled {
///     // the user closed the sign-in sheet
/// }
/// ```
///
/// Messages never contain tokens or secrets.
public struct NineError: Error, Sendable, Hashable, CustomStringConvertible, LocalizedError {
    /// What went wrong, as a string code. Codes 9in sends (`invalid_grant`, `access_denied`,
    /// `invalid_scope`…) come through unchanged; the common ones have a constant.
    public struct Code: RawRepresentable, Hashable, Sendable, ExpressibleByStringLiteral, CustomStringConvertible {
        public let rawValue: String
        public init(rawValue: String) { self.rawValue = rawValue }
        public init(_ rawValue: String) { self.rawValue = rawValue }
        public init(stringLiteral value: String) { self.rawValue = value }
        public var description: String { rawValue }

        /// Nobody is signed in, or the session ended (the refresh token expired or was revoked).
        public static let loginRequired: Code = "login_required"
        /// The user closed the sign-in sheet.
        public static let canceled: Code = "canceled"
        /// The user declined, or 9in refused the sign-in (sent by 9in).
        public static let accessDenied: Code = "access_denied"
        /// The callback's `state` is missing or does not belong to this sign-in.
        public static let invalidState: Code = "invalid_state"
        /// The callback or the discovery document names another issuer.
        public static let invalidIssuer: Code = "invalid_issuer"
        /// The issuer is not `https://` (plain http is only accepted for localhost).
        public static let insecureIssuer: Code = "insecure_issuer"
        /// The browser came back to a URL that is not the redirect URI.
        public static let invalidCallback: Code = "invalid_callback"
        /// The callback has neither a code nor an error.
        public static let missingCode: Code = "missing_code"
        /// The ID token failed a check (signature, issuer, audience, expiry, nonce…).
        public static let invalidIdToken: Code = "invalid_id_token"
        /// The code or refresh token was refused by 9in (sent by 9in).
        public static let invalidGrant: Code = "invalid_grant"
        /// 9in refused the access token (for example at the userinfo endpoint).
        public static let invalidToken: Code = "invalid_token"
        /// The client is configured wrongly (redirect URI, scopes…).
        public static let invalidOptions: Code = "invalid_options"
        /// 9in's answer was not what OAuth / OpenID Connect requires.
        public static let invalidResponse: Code = "invalid_response"
        /// The discovery document could not be loaded or is unusable.
        public static let discoveryFailed: Code = "discovery_failed"
        /// No answer from 9in: offline, timed out, TLS failure. Tokens are kept.
        public static let networkError: Code = "network_error"
        /// 9in answered with an HTTP error without an OAuth error code.
        public static let requestFailed: Code = "request_failed"
        /// The userinfo endpoint failed.
        public static let userinfoFailed: Code = "userinfo_failed"
        /// The system browser could not be shown.
        public static let browserFailed: Code = "browser_failed"
        /// The Keychain refused to read or write the tokens.
        public static let keychainError: Code = "keychain_error"
    }

    public let code: Code
    /// A readable explanation (OAuth's `error_description` when 9in sent one).
    public let message: String?
    /// The HTTP status of 9in's answer, when there was one.
    public let status: Int?

    public init(_ code: Code, _ message: String? = nil, status: Int? = nil) {
        self.code = code
        self.message = message
        self.status = status
    }

    public var description: String {
        guard let message, !message.isEmpty else { return code.rawValue }
        return "\(code.rawValue): \(message)"
    }

    public var errorDescription: String? { description }
}
