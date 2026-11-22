# Changelog

## 0.1.0

First release of the Swift package `Nine` for iOS 15+, macOS 12+, Mac Catalyst 15+ and visionOS 1+.

- `NineClient`: sign-in with the authorization code flow and PKCE (S256) in the system browser
  (`ASWebAuthenticationSession`), `signIn()` and `signUp()` (`prompt=create`), with `state`,
  `nonce` and RFC 9207 `iss` checks and endpoints from OpenID Connect discovery.
- ID tokens verified against the tenant's JWKS (RS256/384/512, PS256/384/512, ES256, ES384,
  EdDSA) and their claims (`iss`, `aud`, `azp`, `exp`, `nbf`, `nonce`, `at_hash`).
- `accessToken()`: refreshes before expiry with refresh-token rotation; concurrent calls share
  one refresh (an actor holds the token state). `refresh()`, `authorize(_:)`, `userInfo()`.
- `signOut()`: revokes the refresh token and ends the 9in session in the browser
  (`postLogoutRedirectURI`), or `signOut(endSession: false)`; `logoutURL()`.
- Keychain storage by default (`KeychainCredentialStore`, after first unlock, this device only),
  `MemoryCredentialStore`, or your own `CredentialStore`.
- SwiftUI: `ObservableObject`, and `Observable` on iOS 17+ / macOS 14+, with `user`,
  `isSignedIn` and `tokens`.
- `Browser` and `HTTPTransport` protocols for tests and custom setups; `NineError` with the
  codes of the other 9in SDKs.
- Issuers must use https (plain http for localhost and loopback, or `allowInsecureIssuer`).
- A SwiftUI example app with UI tests that sign in through the real system browser sheet.
