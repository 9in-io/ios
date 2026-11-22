import Foundation
import Testing
@testable import Nine

@Suite("PKCE, encodings and helpers")
struct PrimitivesTests {
    @Test("PKCE S256 matches the RFC 7636 appendix B example")
    func rfc7636Example() {
        #expect(PKCE.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test("Code verifiers are 64 unreserved characters and never repeat")
    func verifiers() {
        let verifiers = (0..<200).map { _ in PKCE.makeVerifier() }
        #expect(Set(verifiers).count == 200)
        for verifier in verifiers {
            #expect(verifier.count == 64)
            #expect(verifier.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~").contains($0) })
        }
        let state = Random.string(32)
        #expect(state.count == 43)
        #expect(Base64URL.decode(state)?.count == 32)
    }

    @Test("base64url round-trips and refuses other alphabets")
    func base64url() {
        for length in 0..<40 {
            let data = Random.bytes(length)
            let encoded = Base64URL.encode(data)
            #expect(!encoded.contains("=") && !encoded.contains("+") && !encoded.contains("/"))
            #expect(Base64URL.decode(encoded) == data)
        }
        #expect(Base64URL.decode("ab+c") == nil)
        #expect(Base64URL.decode("abc=") == nil)
        #expect(Base64URL.decode("a") == nil)
        #expect(Base64URL.decode("é") == nil)
        #expect(Base64URL.decode("") == Data())
    }

    @Test("Constant-time comparison")
    func constantTime() {
        #expect(constantTimeEquals("abc", "abc"))
        #expect(!constantTimeEquals("abc", "abd"))
        #expect(!constantTimeEquals("abc", "abcd"))
        #expect(constantTimeEquals("", ""))
    }

    @Test("Form encoding escapes everything but unreserved characters")
    func formEncoding() {
        let body = FormEncoding.encode([("redirect_uri", "com.acme.app:/callback"), ("login_hint", "a+b@x.com"), ("scope", "openid profile"), ("x", "ü&=")])
        #expect(String(decoding: body, as: UTF8.self) == "redirect_uri=com.acme.app%3A%2Fcallback&login_hint=a%2Bb%40x.com&scope=openid%20profile&x=%C3%BC%26%3D")
        #expect(FormEncoding.decode(body) == ["redirect_uri": "com.acme.app:/callback", "login_hint": "a+b@x.com", "scope": "openid profile", "x": "ü&="])
    }

    @Test("JSON values decode with their types")
    func jsonValues() throws {
        let object = try #require(JSON.object(Data(#"{"s":"x","n":1794200000,"f":1.5,"b":true,"z":false,"a":[1,"two"],"o":{"k":null},"nul":null}"#.utf8)))
        #expect(object["s"] == "x")
        #expect(object["n"]?.intValue == 1_794_200_000)
        #expect(object["f"]?.doubleValue == 1.5)
        #expect(object["f"]?.intValue == nil)
        #expect(object["b"]?.boolValue == true)
        #expect(object["z"]?.boolValue == false)
        #expect(object["b"]?.doubleValue == nil)
        #expect(object["a"] == [1, "two"])
        #expect(object["o"]?["k"] == .null)
        #expect(object["nul"]?.isNull == true)
        #expect(JSON.object(Data("[1]".utf8)) == nil)
        #expect(JSON.object(Data("nope".utf8)) == nil)
        let round = try JSONDecoder().decode([String: JSONValue].self, from: JSONEncoder().encode(object))
        #expect(round == object)
    }

    @Test("JWT decoding refuses malformed tokens")
    func jwtDecoding() {
        #expect(JWT("a.b") == nil)
        #expect(JWT("a.b.c.d") == nil)
        #expect(JWT("!!.e30.") == nil)
        #expect(JWT("e30.W10.") == nil) // payload is an array
        let token = TestJWT.unsigned(["sub": "x"])
        #expect(JWT(token)?.claims["sub"] == "x")
        #expect(JWT(token)?.signature.isEmpty == true)
    }

    @Test("DER lengths and integers")
    func der() {
        #expect(DER.length(5) == [5])
        #expect(DER.length(0x80) == [0x81, 0x80])
        #expect(DER.length(0x0101) == [0x82, 0x01, 0x01])
        #expect(DER.integer(Data([0x00, 0x00, 0x7F])) == [0x02, 0x01, 0x7F])
        #expect(DER.integer(Data([0x80])) == [0x02, 0x02, 0x00, 0x80])
        #expect(JWS.bitLength(Data([0x00, 0x01, 0x00])) == 9)
        #expect(JWS.bitLength(Data(repeating: 0xFF, count: 256)) == 2048)
    }

    @Test("TokenSet never prints its tokens")
    func redaction() {
        let tokens = TokenSet(accessToken: "secret-access", idToken: "secret-id", refreshToken: "secret-refresh", expiresAt: Date(), scope: "openid")
        var dumped = ""
        dump(tokens, to: &dumped)
        for text in [tokens.description, tokens.debugDescription, String(describing: tokens), "\(tokens)", dumped] {
            #expect(!text.contains("secret"), "\(text)")
        }
        #expect(tokens.description.contains("refreshToken: present"))
    }

    @Test("TokenSet expiry with leeway")
    func expiry() {
        let now = Date()
        let tokens = TokenSet(accessToken: "a", expiresAt: now.addingTimeInterval(90))
        #expect(!tokens.isExpired(now: now))
        #expect(!tokens.isExpired(leeway: 60, now: now))
        #expect(tokens.isExpired(leeway: 120, now: now))
        #expect(tokens.isExpired(now: now.addingTimeInterval(90)))
    }

    @Test("NineError text and codes")
    func errors() {
        let error = NineError(.accessDenied, "the user declined", status: 400)
        #expect(error.description == "access_denied: the user declined")
        #expect(error.localizedDescription == "access_denied: the user declined")
        #expect(NineError(.loginRequired).description == "login_required")
        #expect(NineError.Code(rawValue: "invalid_scope") == "invalid_scope")
        #expect(NineError.Code.canceled.rawValue == "canceled")
    }

    @Test("NineUser reads the standard claims")
    func userClaims() throws {
        let user = NineUser(claims: ["sub": "usr_1", "email": "j@x.com", "email_verified": true, "name": "J", "given_name": "Ja", "family_name": "Ne",
                                     "picture": "https://x.com/p.png", "phone_number": "+447700900000", "phone_number_verified": false,
                                     "amr": ["pwd", "mfa"], "auth_time": 1_794_199_000, "plan": "pro"])
        #expect(user.id == "usr_1")
        #expect(user.email == "j@x.com")
        #expect(user.emailVerified == true)
        #expect(user.givenName == "Ja")
        #expect(user.familyName == "Ne")
        #expect(user.picture == URL(string: "https://x.com/p.png"))
        #expect(user.phoneNumberVerified == false)
        #expect(user.amr == ["pwd", "mfa"])
        #expect(user.authTime == Date(timeIntervalSince1970: 1_794_199_000))
        #expect(user["plan"]?.stringValue == "pro")
        let decoded = try JSONDecoder().decode(NineUser.self, from: JSONEncoder().encode(user))
        #expect(decoded == user)
    }
}
