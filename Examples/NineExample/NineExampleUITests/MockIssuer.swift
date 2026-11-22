import CryptoKit
import Foundation
import Network

/// A stand-in for a 9in tenant on 127.0.0.1, run by the UI test: discovery, JWKS, an
/// authorization endpoint that approves at once (302 to the app's redirect URI), the token
/// endpoint with PKCE and refresh rotation, userinfo, revocation and RP-initiated logout.
/// The app talks to it through the real system browser (ASWebAuthenticationSession).
final class MockIssuer: @unchecked Sendable {
    let clientId = "app_example"
    let email = "jane@example.com"
    private let sub = "usr_example"
    private let key = Curve25519.Signing.PrivateKey()
    private let listener: NWListener
    private let queue = DispatchQueue(label: "mock-issuer")
    private let lock = NSLock()
    private var grants: [String: (challenge: String, nonce: String, redirect: String)] = [:]
    private var refreshTokens: Set<String> = []
    private var accessTokens: Set<String> = []
    private var log: [String] = []
    private(set) var port: UInt16 = 0

    var issuer: String { "http://127.0.0.1:\(port)" }
    /// "METHOD /path" of every request, in order.
    var requests: [String] { lock.lock(); defer { lock.unlock() }; return log }

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() throws {
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            connection.start(queue: self.queue)
            self.receive(connection, Data())
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 10) == .success, let port = listener.port?.rawValue else {
            throw URLError(.cannotConnectToHost)
        }
        self.port = port
    }

    func stop() { listener.cancel() }

    // MARK: HTTP

    private func receive(_ connection: NWConnection, _ buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buffer[..<end.lowerBound], as: UTF8.self)
                var lines = head.components(separatedBy: "\r\n")
                let start = lines.removeFirst().split(separator: " ").map(String.init)
                var headers: [String: String] = [:]
                for line in lines {
                    guard let colon = line.firstIndex(of: ":") else { continue }
                    headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                }
                let length = Int(headers["content-length"] ?? "0") ?? 0
                if buffer.count - end.upperBound >= length, start.count >= 2 {
                    let body = buffer[end.upperBound..<end.upperBound + length]
                    let response = self.handle(method: start[0], target: start[1], headers: headers, body: Data(body))
                    connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
                    return
                }
            }
            if complete || error != nil { connection.cancel(); return }
            self.receive(connection, buffer)
        }
    }

    private func response(_ status: Int, json: [String: Any]? = nil, location: String? = nil, html: String? = nil) -> Data {
        var body = Data()
        var head = "HTTP/1.1 \(status) X\r\nConnection: close\r\nCache-Control: no-store\r\n"
        if let json {
            body = try! JSONSerialization.data(withJSONObject: json)
            head += "Content-Type: application/json\r\n"
        } else if let html {
            body = Data(html.utf8)
            head += "Content-Type: text/html; charset=utf-8\r\n"
        }
        if let location { head += "Location: \(location)\r\n" }
        head += "Content-Length: \(body.count)\r\n\r\n"
        return Data(head.utf8) + body
    }

    private func handle(method: String, target: String, headers: [String: String], body: Data) -> Data {
        let components = URLComponents(string: "http://x\(target)")!
        let path = components.path
        lock.lock(); log.append("\(method) \(path)"); lock.unlock()
        let query = Dictionary((components.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        switch (method, path) {
        case ("GET", "/.well-known/openid-configuration"):
            return response(200, json: [
                "issuer": issuer,
                "authorization_endpoint": "\(issuer)/oauth/authorize",
                "token_endpoint": "\(issuer)/oauth/token",
                "userinfo_endpoint": "\(issuer)/oauth/userinfo",
                "jwks_uri": "\(issuer)/.well-known/jwks.json",
                "end_session_endpoint": "\(issuer)/oauth/logout",
                "revocation_endpoint": "\(issuer)/oauth/revoke",
                "code_challenge_methods_supported": ["S256"],
                "authorization_response_iss_parameter_supported": true,
            ])
        case ("GET", "/.well-known/jwks.json"):
            return response(200, json: ["keys": [["kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig", "x": b64(key.publicKey.rawRepresentation)]]])
        case ("GET", "/oauth/authorize"):
            guard query["client_id"] == clientId, query["code_challenge_method"] == "S256", let redirect = query["redirect_uri"], let state = query["state"] else {
                return response(400, html: "<h1>Bad request</h1>")
            }
            let code = UUID().uuidString
            lock.lock(); grants[code] = (query["code_challenge"] ?? "", query["nonce"] ?? "", redirect); lock.unlock()
            return response(302, location: "\(redirect)?code=\(code)&state=\(escape(state))&iss=\(escape(issuer))")
        case ("GET", "/oauth/logout"):
            if let redirect = query["post_logout_redirect_uri"] {
                return response(302, location: "\(redirect)?state=\(escape(query["state"] ?? ""))")
            }
            return response(200, html: "<h1>You've signed out</h1>")
        case ("POST", "/oauth/token"):
            return token(form(body))
        case ("GET", "/oauth/userinfo"):
            let bearer = (headers["authorization"] ?? "").replacingOccurrences(of: "Bearer ", with: "")
            lock.lock(); let known = accessTokens.contains(bearer); lock.unlock()
            return known ? response(200, json: ["sub": sub, "email": email, "email_verified": true]) : response(401, json: ["error": "invalid_token"])
        case ("POST", "/oauth/revoke"):
            let token = form(body)["token"] ?? ""
            lock.lock(); refreshTokens.remove(token); lock.unlock()
            return response(200, json: [:])
        default:
            return response(404, json: ["error": "not_found"])
        }
    }

    private func token(_ form: [String: String]) -> Data {
        guard form["client_id"] == clientId else { return response(401, json: ["error": "invalid_client"]) }
        var nonce: String?
        switch form["grant_type"] {
        case "authorization_code":
            lock.lock(); let grant = grants.removeValue(forKey: form["code"] ?? ""); lock.unlock()
            guard let grant, form["redirect_uri"] == grant.redirect,
                  b64(Data(SHA256.hash(data: Data((form["code_verifier"] ?? "").utf8)))) == grant.challenge
            else { return response(400, json: ["error": "invalid_grant", "error_description": "code or PKCE verifier refused"]) }
            nonce = grant.nonce
        case "refresh_token":
            lock.lock(); let known = refreshTokens.remove(form["refresh_token"] ?? "") != nil; lock.unlock()
            guard known else { return response(400, json: ["error": "invalid_grant"]) }
        default:
            return response(400, json: ["error": "unsupported_grant_type"])
        }
        let accessToken = "at_\(UUID().uuidString)"
        let refreshToken = "rt_\(UUID().uuidString)"
        lock.lock(); accessTokens.insert(accessToken); refreshTokens.insert(refreshToken); lock.unlock()
        let now = Int(Date().timeIntervalSince1970)
        var claims: [String: Any] = [
            "iss": issuer, "sub": sub, "aud": clientId, "azp": clientId, "iat": now, "exp": now + 3600, "auth_time": now,
            "amr": ["pwd"], "email": email, "email_verified": true, "name": "Jane Example",
        ]
        if let nonce { claims["nonce"] = nonce }
        let hash = Data(SHA512.hash(data: Data(accessToken.utf8)))
        claims["at_hash"] = b64(hash.prefix(32))
        return response(200, json: [
            "access_token": accessToken, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refreshToken,
            "id_token": jwt(claims), "scope": "openid profile email offline_access",
        ])
    }

    private func jwt(_ claims: [String: Any]) -> String {
        let header = b64(try! JSONSerialization.data(withJSONObject: ["alg": "EdDSA", "kid": "k1", "typ": "JWT"]))
        let payload = b64(try! JSONSerialization.data(withJSONObject: claims))
        let signature = try! key.signature(for: Data("\(header).\(payload)".utf8))
        return "\(header).\(payload).\(b64(signature))"
    }

    private func form(_ body: Data) -> [String: String] {
        var fields: [String: String] = [:]
        for pair in String(decoding: body, as: UTF8.self).split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map { String($0).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String($0) }
            fields[parts[0]] = parts.count > 1 ? parts[1] : ""
        }
        return fields
    }

    private func b64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func escape(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
    }
}
