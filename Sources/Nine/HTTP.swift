import Foundation

/// Sends the SDK's HTTP requests (discovery, keys, token, userinfo, revocation). The default is
/// `URLSessionTransport`; pass your own to add logging or certificate pinning, or in tests.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// The default transport: an ephemeral `URLSession` (no cookies, no cache) with a 10-second
/// timeout that never follows a redirect to another origin.
public final class URLSessionTransport: HTTPTransport, @unchecked Sendable {
    private let session: URLSession
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 10) {
        self.timeout = timeout
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout * 3
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        session = URLSession(configuration: configuration, delegate: SameOriginRedirects(), delegateQueue: nil)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var request = request
        request.timeoutInterval = timeout
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }
}

/// Follows a redirect only within the same origin (scheme, host and port), so a token or a
/// credential is never sent to another server; otherwise the 3xx answer is returned as is.
final class SameOriginRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        guard let from = task.originalRequest?.url, let to = request.url, Self.sameOrigin(from, to) else { return nil }
        return request
    }

    static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
        func port(_ url: URL) -> Int? { url.port ?? (url.scheme?.lowercased() == "https" ? 443 : url.scheme?.lowercased() == "http" ? 80 : nil) }
        return a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased() && port(a) == port(b)
    }
}

/// JSON over the transport, with 9in's error bodies turned into `NineError`.
struct HTTPClient: Sendable {
    let transport: HTTPTransport

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await transport.send(request)
        } catch let error as NineError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch {
            throw NineError(.networkError, error.localizedDescription)
        }
    }

    /// GET a JSON object.
    func getJSON(_ url: URL, bearer: String? = nil, failure: NineError.Code = .requestFailed) async throws -> [String: JSONValue] {
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let bearer { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await send(request)
        return try Self.object(data, response, failure: failure)
    }

    /// POST a form and read the JSON answer.
    func postForm(_ url: URL, _ fields: [(String, String)]) async throws -> [String: JSONValue] {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = FormEncoding.encode(fields)
        let (data, response) = try await send(request)
        return try Self.object(data, response, failure: .requestFailed)
    }

    static func object(_ data: Data, _ response: HTTPURLResponse, failure: NineError.Code) throws -> [String: JSONValue] {
        let json = JSON.object(data)
        guard (200..<300).contains(response.statusCode) else {
            throw error(json, status: response.statusCode, fallback: failure)
        }
        if data.isEmpty { return [:] }
        guard let json else { throw NineError(.invalidResponse, "the answer is not a JSON object", status: response.statusCode) }
        return json
    }

    static func error(_ json: [String: JSONValue]?, status: Int, fallback: NineError.Code) -> NineError {
        let code = json?["error"]?.stringValue.map(NineError.Code.init(rawValue:)) ?? fallback
        let message = json?["error_description"]?.stringValue ?? "HTTP \(status)"
        return NineError(code, message, status: status)
    }
}
