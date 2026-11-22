import Foundation
@testable import Nine

/// Settings of the live e2e tenants: the file at `NINE_E2E_ENV` (KEY=value lines), with `E2E_*`
/// environment variables taking precedence. Values are never printed.
enum Live {
    static let enabled = ProcessInfo.processInfo.environment["NINE_E2E"] == "1"

    static let settings: [String: String] = {
        var values: [String: String] = [:]
        let environment = ProcessInfo.processInfo.environment
        if let path = environment["NINE_E2E_ENV"], let text = try? String(contentsOfFile: path, encoding: .utf8) {
            for line in text.split(whereSeparator: \.isNewline) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard let eq = trimmed.firstIndex(of: "="), trimmed[..<eq].allSatisfy({ $0.isUppercase || $0.isNumber || $0 == "_" }) else { continue }
                values[String(trimmed[..<eq])] = String(trimmed[trimmed.index(after: eq)...])
            }
        }
        for (key, value) in environment where key.hasPrefix("E2E_") { values[String(key.dropFirst(4))] = value }
        return values
    }()

    static func env(_ name: String) throws -> String {
        guard let value = settings[name], !value.isEmpty else { throw NineError(.invalidOptions, "E2E setting \(name) is missing (NINE_E2E_ENV)") }
        return value
    }

    /// A marker for this run, in the test users' emails.
    static let run = String(Int(Date().timeIntervalSince1970), radix: 36) + String(UInt16.random(in: 0...UInt16.max), radix: 36)
    static let email = "ios-\(run)@sandbox.e2e.test"
}

/// Refuses every redirect, so the caller sees each hop.
final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// Drives 9in's real hosted pages the way a person in the browser would: a cookie jar per host,
/// manual redirects, the sign-in form posted with an identifier and password. It stands in for
/// the system browser through the SDK's `Browser` seam.
final class HostedPageBrowser: Browser, @unchecked Sendable {
    struct Page: Sendable {
        let url: URL
        let status: Int
        let html: String
        var text: String {
            html.replacingOccurrences(of: "<script[\\s\\S]*?</script>", with: " ", options: .regularExpression)
                .replacingOccurrences(of: "<style[\\s\\S]*?</style>", with: " ", options: .regularExpression)
                .replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
                .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
        }
    }

    let identifier: String
    let password: String
    /// How many times the sign-in form had to be filled in (0 for a single sign-on).
    let formsSubmitted = Locked(0)
    /// The page a visit ended on when it didn't come back to the app.
    let lastPage = Locked<Page?>(nil)
    let visits = Locked<[URL]>([])
    /// Changes the callback before the SDK sees it (tests of refused callbacks).
    let tamper = Locked<(@Sendable (URL) -> URL)?>(nil)
    private let jar = Locked<[String: [String: String]]>([:])
    private let session: URLSession

    init(identifier: String, password: String) {
        self.identifier = identifier
        self.password = password
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.timeoutIntervalForRequest = 30
        session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
    }

    func open(_ url: URL, callbackURL: URL, ephemeral: Bool) async throws -> URL {
        visits.withLock { $0.append(url) }
        let callback = try await walk(url, callbackURL: callbackURL)
        return tamper.current?(callback) ?? callback
    }

    private func walk(_ url: URL, callbackURL: URL) async throws -> URL {
        let start = try await follow(url, stopAt: callbackURL)
        if let callback = start.callback { return callback }
        let page = start.page!
        guard page.html.contains("name=\"identifier\"") else {
            lastPage.withLock { $0 = page }
            // 9in's "You're signed out" page, an error page…: the person closes the sheet.
            throw NineError(.canceled, "the browser stayed on a page (HTTP \(page.status))")
        }
        formsSubmitted.withLock { $0 += 1 }
        let action = Self.formAction(page.html, page.url)
        var fields = Self.hiddenFields(page.html)
        fields["identifier"] = identifier
        fields["password"] = password
        fields["action"] = "password"
        let origin = "\(action.scheme!)://\(action.host!)\(action.port.map { ":\($0)" } ?? "")"
        let (response, body) = try await request(action, form: fields, headers: ["Origin": origin, "Referer": page.url.absoluteString])
        guard let location = response.value(forHTTPHeaderField: "Location"), let next = URL(string: location, relativeTo: action)?.absoluteURL else {
            lastPage.withLock { $0 = Page(url: action, status: response.statusCode, html: body) }
            throw NineError(.accessDenied, "the sign-in form was refused (HTTP \(response.statusCode))")
        }
        let done = try await follow(next, stopAt: callbackURL)
        if let callback = done.callback { return callback }
        lastPage.withLock { $0 = done.page }
        throw NineError(.accessDenied, "sign-in did not come back to the app (HTTP \(done.page!.status))")
    }

    private func follow(_ url: URL, stopAt: URL) async throws -> (callback: URL?, page: Page?) {
        var current = url
        for _ in 0..<20 {
            if current.absoluteString.hasPrefix(stopAt.absoluteString) { return (current, nil) }
            let (response, body) = try await request(current)
            if (300..<400).contains(response.statusCode), let location = response.value(forHTTPHeaderField: "Location") {
                current = URL(string: location, relativeTo: current)!.absoluteURL
                continue
            }
            return (nil, Page(url: current, status: response.statusCode, html: body))
        }
        throw NineError(.requestFailed, "too many redirects")
    }

    private func request(_ url: URL, form: [String: String]? = nil, headers: [String: String] = [:]) async throws -> (HTTPURLResponse, String) {
        var request = URLRequest(url: url)
        let host = url.host ?? ""
        let cookies = jar.withLock { $0[host] ?? [:] }
        if !cookies.isEmpty { request.setValue(cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; "), forHTTPHeaderField: "Cookie") }
        request.setValue("9in-e2e-ios/1.0", forHTTPHeaderField: "User-Agent")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let form {
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.httpBody = FormEncoding.encode(form.sorted { $0.key < $1.key })
        }
        let (data, response) = try await session.data(for: request)
        let http = response as! HTTPURLResponse
        let fields = http.allHeaderFields.reduce(into: [String: String]()) { $0["\($1.key)"] = "\($1.value)" }
        let received = HTTPCookie.cookies(withResponseHeaderFields: fields, for: url)
        jar.withLock { jar in
            var hostJar = jar[host] ?? [:]
            for cookie in received {
                if cookie.value.isEmpty || (cookie.expiresDate.map { $0 < Date() } ?? false) {
                    hostJar.removeValue(forKey: cookie.name)
                } else {
                    hostJar[cookie.name] = cookie.value
                }
            }
            jar[host] = hostJar
        }
        return (http, String(decoding: data, as: UTF8.self))
    }

    private static func forms(_ html: String) -> [String] {
        html.components(separatedBy: "<form").dropFirst().map { $0.components(separatedBy: "</form>").first ?? $0 }
    }

    private static func decode(_ value: String) -> String {
        value.replacingOccurrences(of: "&amp;", with: "&").replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&#x27;", with: "'").replacingOccurrences(of: "&#39;", with: "'")
            .replacingOccurrences(of: "&lt;", with: "<").replacingOccurrences(of: "&gt;", with: ">")
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range(at: 1), in: text)
        else { return nil }
        return String(text[range])
    }

    static func hiddenFields(_ html: String) -> [String: String] {
        guard let form = forms(html).first(where: { $0.contains("name=\"identifier\"") }) ?? forms(html).first,
              let regex = try? NSRegularExpression(pattern: "<input\\b[^>]*>")
        else { return [:] }
        var fields: [String: String] = [:]
        for match in regex.matches(in: form, range: NSRange(form.startIndex..., in: form)) {
            let input = String(form[Range(match.range, in: form)!])
            guard input.contains("type=\"hidden\""), let name = firstMatch("name=\"([^\"]+)\"", in: input) else { continue }
            fields[name] = decode(firstMatch("value=\"([^\"]*)\"", in: input) ?? "")
        }
        return fields
    }

    static func formAction(_ html: String, _ pageURL: URL) -> URL {
        let form = forms(html).first(where: { $0.contains("name=\"identifier\"") }) ?? forms(html).first ?? ""
        let action = decode(firstMatch("action=\"([^\"]*)\"", in: form) ?? "")
        return action.isEmpty ? pageURL : URL(string: action, relativeTo: pageURL)!.absoluteURL
    }
}

/// Counts the requests the SDK sends (to check that a refresh happens once).
final class CountingTransport: HTTPTransport, @unchecked Sendable {
    let inner = URLSessionTransport()
    let paths = Locked<[String]>([])

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let form = request.httpBody.map(FormEncoding.decode) ?? [:]
        paths.withLock { $0.append("\(request.httpMethod ?? "GET") \(request.url?.path ?? "") \(form["grant_type"] ?? "")") }
        return try await inner.send(request)
    }

    func count(_ prefix: String) -> Int { paths.current.filter { $0.hasPrefix(prefix) }.count }
}

/// Direct calls to 9in for what the SDK doesn't do (it is a public client): reusing a refresh
/// token, and deleting the test users with the confidential E2E Server client.
enum LiveAPI {
    static func post(_ url: URL, _ form: [String: String], basic: (String, String)? = nil) async throws -> (Int, [String: JSONValue]) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let (user, password) = basic {
            let credentials = "\(FormEncoding.escape(user)):\(FormEncoding.escape(password))"
            request.setValue("Basic \(Data(credentials.utf8).base64EncodedString())", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = FormEncoding.encode(form.sorted { $0.key < $1.key })
        let (data, response) = try await URLSessionTransport().send(request)
        return (response.statusCode, JSON.object(data) ?? [:])
    }

    /// Deletes the sandbox user with `email`; true when it existed.
    static func deleteUser(email: String) async throws -> Bool {
        let issuer = try Live.env("SANDBOX_ISSUER")
        let (status, token) = try await post(URL(string: "\(issuer)/oauth/token")!, ["grant_type": "client_credentials", "scope": "management:users:read management:users:write"],
                                             basic: (try Live.env("SERVER_CLIENT_ID"), try Live.env("SERVER_CLIENT_SECRET")))
        guard status == 200, let accessToken = token["access_token"]?.stringValue else { throw NineError(.requestFailed, "management token: HTTP \(status)") }
        var lookup = URLRequest(url: URL(string: "\(issuer)/api/v1/users/lookup?email=\(FormEncoding.escape(email))")!)
        lookup.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSessionTransport().send(lookup)
        if response.statusCode == 404 { return false }
        guard response.statusCode == 200, let id = JSON.object(data)?["user"]?["id"]?.stringValue else { throw NineError(.requestFailed, "lookup: HTTP \(response.statusCode)") }
        var delete = URLRequest(url: URL(string: "\(issuer)/api/v1/users/\(FormEncoding.escape(id))")!)
        delete.httpMethod = "DELETE"
        delete.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let (_, deleted) = try await URLSessionTransport().send(delete)
        guard deleted.statusCode == 204 || deleted.statusCode == 404 else { throw NineError(.requestFailed, "delete: HTTP \(deleted.statusCode)") }
        return true
    }
}
