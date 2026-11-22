import Foundation

/// The tokens of a signed-in user. Printing or dumping a `TokenSet` never shows the tokens.
public struct TokenSet: Codable, Sendable, Hashable {
    /// For your API: send it as `Authorization: Bearer …`. Get it with `NineClient.accessToken()`,
    /// which refreshes it first when it is about to expire.
    public var accessToken: String
    /// `Bearer`.
    public var tokenType: String
    /// The ID token of the sign-in (or of the last refresh), already verified.
    public var idToken: String?
    /// Present when the `offline_access` scope was granted. 9in rotates it on every refresh.
    public var refreshToken: String?
    /// When the access token expires.
    public var expiresAt: Date
    /// The scopes granted, space-separated.
    public var scope: String?

    public init(accessToken: String, tokenType: String = "Bearer", idToken: String? = nil, refreshToken: String? = nil, expiresAt: Date, scope: String? = nil) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.idToken = idToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.scope = scope
    }

    /// True when the access token expires within `leeway` seconds.
    public func isExpired(leeway: TimeInterval = 0, now: Date = Date()) -> Bool {
        expiresAt.timeIntervalSince(now) <= leeway
    }
}

extension TokenSet: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "TokenSet(expiresAt: \(expiresAt), scope: \(scope ?? "nil"), idToken: \(idToken == nil ? "none" : "present"), refreshToken: \(refreshToken == nil ? "none" : "present"))"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "accessToken": "<redacted>",
            "tokenType": tokenType,
            "idToken": idToken == nil ? "nil" : "<redacted>",
            "refreshToken": refreshToken == nil ? "nil" : "<redacted>",
            "expiresAt": expiresAt,
            "scope": scope as Any,
        ])
    }
}

/// The signed-in user: the claims of the verified ID token (or of the userinfo endpoint), with
/// the standard ones as properties. Other claims, custom fields included, are in `claims`.
public struct NineUser: Sendable, Hashable, Codable, Identifiable {
    /// Every claim, as 9in sent it (snake_case names, unchanged).
    public let claims: [String: JSONValue]

    public init(claims: [String: JSONValue]) {
        self.claims = claims
    }

    public init(from decoder: Decoder) throws {
        claims = try decoder.singleValueContainer().decode([String: JSONValue].self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(claims)
    }

    /// The user's id at 9in (`sub`).
    public var id: String { sub }
    public var sub: String { claims["sub"]?.stringValue ?? "" }
    public var email: String? { claims["email"]?.stringValue }
    public var emailVerified: Bool? { claims["email_verified"]?.boolValue }
    public var name: String? { claims["name"]?.stringValue }
    public var givenName: String? { claims["given_name"]?.stringValue }
    public var familyName: String? { claims["family_name"]?.stringValue }
    public var nickname: String? { claims["nickname"]?.stringValue }
    public var preferredUsername: String? { claims["preferred_username"]?.stringValue }
    public var picture: URL? { claims["picture"]?.stringValue.flatMap(URL.init(string:)) }
    public var phoneNumber: String? { claims["phone_number"]?.stringValue }
    public var phoneNumberVerified: Bool? { claims["phone_number_verified"]?.boolValue }
    public var locale: String? { claims["locale"]?.stringValue }
    /// How the user signed in: `pwd`, `otp`, `social`, `fed`, `link`, and `mfa` after a second factor.
    public var amr: [String] { claims["amr"]?.arrayValue?.compactMap(\.stringValue) ?? [] }
    /// When the user signed in.
    public var authTime: Date? { claims["auth_time"]?.doubleValue.map(Date.init(timeIntervalSince1970:)) }

    /// Any claim by name, e.g. `user["plan"]?.stringValue`.
    public subscript(claim: String) -> JSONValue? { claims[claim] }
}
