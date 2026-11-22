9in iOS SDK
===========

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official iOS SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO, for
apps in Swift on iOS, macOS and visionOS.

`Nine` signs users in to your app with your tenant's hosted login page, in the system browser.
It has no dependencies: AuthenticationServices, CryptoKit, Security and URLSession.

- **Sign users in with the system browser**: authorization code flow with PKCE in
  `ASWebAuthenticationSession`, never a web view, with `state`, `nonce` and issuer (RFC 9207) checks.
- **Verified ID tokens**: the signature against your tenant's keys (RS256/384/512, PS256/384/512,
  ES256, ES384, EdDSA) and every claim (`iss`, `aud`, `azp`, `exp`, `nonce`, `at_hash`).
- **Tokens kept for you**: in the Keychain (this device only), access tokens refreshed before
  they expire, refresh tokens rotated and saved, and concurrent requests sharing one refresh.
- **SwiftUI-ready**: `NineClient` is an `ObservableObject`, and `Observable` on iOS 17 and later;
  `user` and `isSignedIn` update on the main actor.
- **Sign out** at 9in too: the refresh token is revoked and the 9in session ended.
- **Easy to test**: the browser, the token store and the HTTP transport are protocols.

Requires iOS 15, macOS 12, Mac Catalyst 15 or visionOS 1 and later, and Xcode 16 or later.

```swift
.package(url: "https://github.com/9in-io/ios", from: "0.1.0")
// and in your target's dependencies:
.product(name: "Nine", package: "ios")
```

In Xcode: **File → Add Package Dependencies…**, enter `https://github.com/9in-io/ios`, and add the
`Nine` library to your app target. The guide is [Mobile and desktop apps](https://9in.io/docs/native-apps/)
in the 9in docs.

| Building with | Use |
|---|---|
| Android | [`com.github.9in-io:android`](https://github.com/9in-io/android) |
| React | [`@9in-io/react`](https://github.com/9in-io/react) |
| JavaScript in the browser | [`@9in-io/sdk`](https://github.com/9in-io/sdk) |
| Your API, in Node.js, PHP, Python or Go | [`@9in-io/sdk/server`](https://github.com/9in-io/sdk), [`9in/php-sdk`](https://github.com/9in-io/php-sdk), [`9in`](https://github.com/9in-io/python-sdk), [`github.com/9in-io/go-sdk`](https://github.com/9in-io/go-sdk) |

## Set up the application

In the 9in console, **Applications → Create application → Native / Mobile**. Add your redirect
URI to **Allowed callback URLs**: a custom scheme in reverse-domain form, such as
`com.acme.app:/callback`. Nothing else is needed in Xcode: `ASWebAuthenticationSession` catches
the redirect itself, without a URL type in Info.plist.

To come back to the app after sign-out, add a URI such as `com.acme.app:/signed-out` to
**Allowed logout URLs** and pass it as `postLogoutRedirectURI`.

## Sign users in

```swift
import Nine

let nine = NineClient(
    issuer: "https://acme.9in.io",        // or your custom domain
    clientId: "YOUR_CLIENT_ID",
    redirectURI: "com.acme.app:/callback"
)

let user = try await nine.signIn()        // opens the hosted login page
print(user.email ?? user.sub)

try await nine.signUp()                   // opens the sign-up form (prompt=create)
```

`signIn()` opens the sign-in sheet, checks the answer, exchanges the code with the PKCE verifier,
verifies the ID token and keeps the tokens in the Keychain. It returns the signed-in user: the
ID token's claims, with `sub`, `email`, `emailVerified`, `name`, `givenName`, `familyName`,
`picture`, `phoneNumber`, `locale`, `amr` and `authTime` as properties, and any claim (custom
fields included) by name: `user["plan"]?.stringValue`.

Create one client for your app and share it. At the next launch the client finds the session
in the Keychain at once: `nine.isSignedIn` and `nine.user` are set before any network call.

`signIn` takes `loginHint` (prefills the identifier), `prompt` (`.login` asks for the password
again even with a 9in session, `.selectAccount`, `.consent`), `maxAge`, extra authorization
`parameters` (they never replace `state`, `nonce` or PKCE) and `ephemeral`.

If the user closes the sheet, `signIn()` throws `NineError` with the code `.canceled`:

```swift
do {
    try await nine.signIn()
} catch let error as NineError where error.code == .canceled {
    // closed the sheet: nothing to do
}
```

## SwiftUI

```swift
import Nine
import SwiftUI

@main
struct AcmeApp: App {
    @StateObject private var nine = NineClient(issuer: "https://acme.9in.io", clientId: "YOUR_CLIENT_ID", redirectURI: "com.acme.app:/callback")

    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(nine)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var nine: NineClient

    var body: some View {
        if let user = nine.user {
            VStack {
                Text("Hello \(user.name ?? user.email ?? user.sub)")
                Button("Sign out") { Task { try? await nine.signOut() } }
            }
        } else {
            Button("Sign in") { Task { try? await nine.signIn() } }
        }
    }
}
```

On iOS 17 and later you can keep it in `@State` instead, since `NineClient` is also `Observable`.
`isSignedIn` turns false on sign-out and when 9in refuses the refresh token (the session ended,
the user was blocked or signed out everywhere).

[`Examples/NineExample`](Examples/NineExample) is a complete SwiftUI app.

## Call your API

Pass your API's identifier as `audience` to get access tokens for it:

```swift
let nine = NineClient(issuer: "https://acme.9in.io", clientId: "YOUR_CLIENT_ID",
                      redirectURI: "com.acme.app:/callback", audience: "https://api.acme.com")

let token = try await nine.accessToken()   // refreshed first when it expires within a minute

var request = URLRequest(url: URL(string: "https://api.acme.com/orders")!)
request = try await nine.authorize(request)  // adds Authorization: Bearer …
let (data, _) = try await URLSession.shared.data(for: request)
```

`accessToken()` returns the stored token while it is valid for more than a minute, and
refreshes it otherwise. 9in rotates refresh tokens: every refresh returns a new one, which is
saved at once. Calls made at the same time share one refresh, so they don't race each other.
`refresh()` refreshes now, for example after your API answered 401.

When the refresh token is refused (`invalid_grant`), the user is signed out and
`accessToken()` throws `.loginRequired`. When 9in can't be reached, it throws `.networkError`
and the tokens are kept.

Your API checks these tokens with a server SDK: `verifyAccessToken` from
[`@9in-io/sdk/server`](https://github.com/9in-io/sdk#protect-your-api-server), the
[PHP SDK](https://github.com/9in-io/php-sdk), [Python](https://github.com/9in-io/python-sdk) or
[Go](https://github.com/9in-io/go-sdk).

`userInfo()` fetches the user's current profile from the userinfo endpoint.

## Sign out

```swift
try await nine.signOut()
```

This forgets the tokens, revokes the refresh token at 9in, and ends the 9in session in the
system browser, so the next sign-in asks for the password again. With a `postLogoutRedirectURI`
the sheet closes by itself; without one, the user closes 9in's "You've signed out" page. The user
is signed out of the app even if they cancel that step.

`signOut(endSession: false)` signs out of the app only (the tokens are still revoked): the next
`signIn()` finds the 9in session and doesn't ask for the password. `logoutURL()` gives the
end-session URL if you want to open it yourself.

## Configuration

`NineClient(configuration:store:browser:transport:)` takes every option:

```swift
let nine = NineClient(configuration: .init(
    issuer: "https://acme.9in.io",
    clientId: "YOUR_CLIENT_ID",
    redirectURI: "com.acme.app:/callback",
    scopes: ["openid", "profile", "email", "offline_access"],   // the default
    audience: "https://api.acme.com",
    postLogoutRedirectURI: "com.acme.app:/signed-out",
    locale: "de",                                  // language of the hosted pages
    prefersEphemeralWebBrowserSession: false,      // true: no cookies shared with Safari
    allowInsecureIssuer: false,
    clockSkew: 60                                  // seconds tolerated in ID token times
))
```

| Option | |
|---|---|
| `scopes` | `openid` is required. `offline_access` gives a refresh token; without it the user signs in again when the access token expires. |
| `prefersEphemeralWebBrowserSession` | A private browser session: no single sign-on with Safari and no "wants to use … to sign in" prompt. Sign-out then has no browser step. `signIn(ephemeral:)` overrides it for one sign-in. |
| `locale` | Sent as `ui_locales`. |

### Universal links

A redirect URI can be an `https://` universal link instead of a custom scheme on iOS 17.4,
macOS 14.4 and visionOS 1.1 and later. The app needs the `webcredentials:` associated domain for
that host. On earlier versions, use a custom scheme.

### Where tokens are kept

`KeychainCredentialStore` keeps the session as a generic password readable after the first
unlock and never synced or restored to another device
(`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`). To share it with your extensions, pass an
access group:

```swift
NineClient(configuration: configuration, store: KeychainCredentialStore(accessGroup: "TEAMID.com.acme.shared"))
```

`MemoryCredentialStore` keeps nothing between launches (previews, tests). Any type conforming to
`CredentialStore` (`read`, `write`, `delete` of `Data` by key) works too. On macOS, apps signed
with a team use the data protection keychain like iOS; unsigned builds and command-line tools
use the login keychain.

## Test your app

The browser step is a protocol, so tests can sign in without a sheet: implement
`Browser.open(_:callbackURL:ephemeral:)` and return the callback URL your fake authorization
server would redirect to. Pair it with `MemoryCredentialStore` and an `HTTPTransport` that
answers the token endpoint. This package's own tests drive 9in's real hosted pages this way.

## Issuers must use https

`NineClient` refuses an issuer that is not `https://` (`insecure_issuer`), so a typo cannot send
tokens in clear text, and checks that the discovery document is for that issuer and that its
endpoints use https. Plain http is accepted for `localhost`, `*.localhost` and loopback
addresses; for other development hosts, set `allowInsecureIssuer: true`.

A wrong configuration doesn't crash the app: every call throws the `NineError` that says what is
wrong (`insecure_issuer`, `invalid_issuer`, `invalid_options`).

## Errors

Every failure is a `NineError` with a `code`, a `message` and, when 9in answered with an error,
the HTTP `status`. Messages never contain tokens. Codes 9in sends come through unchanged.
Cancelling the `Task` that awaits a call throws Swift's `CancellationError`, as usual.

| Code | When |
|---|---|
| `canceled` | The user closed the sign-in sheet |
| `access_denied`, `login_required`, `invalid_scope`… | Sent by 9in on the callback |
| `login_required` | Nobody is signed in, or the session ended (the user is then signed out) |
| `invalid_state`, `invalid_issuer`, `invalid_callback`, `missing_code` | The callback failed a check |
| `invalid_id_token` | The ID token failed a check (signature, issuer, audience, expiry, nonce) |
| `invalid_grant` | 9in refused the code |
| `network_error` | 9in couldn't be reached (offline, timeout) |
| `insecure_issuer`, `invalid_options`, `discovery_failed` | Configuration problems |
| `keychain_error` | The Keychain refused to save or read the tokens |

## Security

- PKCE S256 on every sign-in, with a new `state`, `nonce` and verifier each time; `state` is
  compared in constant time and is single-use.
- The callback must be the redirect URI; `iss` must be your issuer, and is required because 9in
  always sends it (RFC 9207).
- ID tokens are verified against the tenant's JWKS (cached 10 minutes, fetched again once for a
  new key, unknown keys then ignored for a minute). The key decides the algorithm; `alg: none`,
  HMAC and access tokens are refused; RSA keys need 2048 bits or more.
- Refresh tokens are rotated and saved on every refresh. A refresh that finishes after a
  sign-out or a new sign-in is thrown away.
- HTTP goes through an ephemeral `URLSession`: no cookies, no cache, a 10-second timeout, and no
  redirects to another origin.
- `TokenSet` and `NineClient` never print tokens (`print`, `dump`, the debugger).

## Development

```bash
swift test                                   # macOS (Xcode 16+)
xcodebuild test -scheme Nine -destination 'platform=iOS Simulator,name=iPhone 17'
```

The live end-to-end tests sign in through 9in's real hosted pages on a test tenant and delete the
user afterwards. They are skipped unless `NINE_E2E=1` is set:

```bash
NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e swift test --filter Live
```

The example app's UI tests run a full sign-in through `ASWebAuthenticationSession` against a mock
issuer:

```bash
cd Examples/NineExample
xcodebuild test -scheme NineExample -destination 'platform=iOS Simulator,name=iPhone 17'
```

Report bugs in [issues](https://github.com/9in-io/ios/issues).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).
