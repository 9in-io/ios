import Foundation
import Network
import Testing
@testable import Nine

/// A tiny HTTP/1.1 server on 127.0.0.1 for testing the real URLSession transport.
final class LocalServer: @unchecked Sendable {
    struct Seen: Sendable {
        let path: String
        let headers: [String: String]
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "nine.tests.server")
    let seen = Locked<[Seen]>([])
    private(set) var port: UInt16 = 0
    /// path → (status, headers, body); `{port}` in a header is replaced by the port.
    let routes: [String: (Int, [String: String], String)]

    init(routes: [String: (Int, [String: String], String)]) throws {
        self.routes = routes
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() async throws {
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            connection.start(queue: self.queue)
            self.receive(connection, Data())
        }
        let started = Locked(false)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if !started.withLock({ let was = $0; $0 = true; return was }) { continuation.resume() }
                case let .failed(error):
                    if !started.withLock({ let was = $0; $0 = true; return was }) { continuation.resume(throwing: error) }
                default: break
                }
            }
            listener.start(queue: queue)
        }
        port = listener.port?.rawValue ?? 0
    }

    func stop() { listener.cancel() }

    private func receive(_ connection: NWConnection, _ buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var buffer = buffer
            if let data { buffer.append(data) }
            if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buffer[..<end.lowerBound], as: UTF8.self)
                var lines = head.components(separatedBy: "\r\n")
                let requestLine = lines.removeFirst().split(separator: " ")
                var headers: [String: String] = [:]
                for line in lines {
                    guard let colon = line.firstIndex(of: ":") else { continue }
                    headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                }
                let length = Int(headers["content-length"] ?? "0") ?? 0
                if buffer.count - end.upperBound >= length {
                    let path = requestLine.count > 1 ? String(requestLine[1]) : "/"
                    self.seen.withLock { $0.append(Seen(path: path, headers: headers)) }
                    self.respond(connection, path: path)
                    return
                }
            }
            if complete || error != nil { connection.cancel(); return }
            self.receive(connection, buffer)
        }
    }

    private func respond(_ connection: NWConnection, path: String) {
        let route = routes[String(path.split(separator: "?").first ?? "")] ?? (404, [:], #"{"error":"not_found"}"#)
        var head = "HTTP/1.1 \(route.0) X\r\nContent-Length: \(route.2.utf8.count)\r\nConnection: close\r\n"
        for (name, value) in route.1 { head += "\(name): \(value.replacingOccurrences(of: "{port}", with: String(port)))\r\n" }
        let response = Data((head + "\r\n" + route.2).utf8)
        connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
    }
}

@Suite("URLSession transport")
struct TransportTests {
    private func server() async throws -> LocalServer {
        let server = try LocalServer(routes: [
            "/json": (200, ["Content-Type": "application/json"], #"{"ok":true}"#),
            "/same-origin": (302, ["Location": "http://127.0.0.1:{port}/json"], ""),
            "/cross-origin": (302, ["Location": "http://localhost:{port}/json"], ""),
            "/oauth-error": (400, ["Content-Type": "application/json"], #"{"error":"invalid_request","error_description":"bad input"}"#),
            "/plain-error": (500, [:], "oops"),
            "/not-json": (200, [:], "<html>"),
            "/cookie": (200, ["Set-Cookie": "sid=abc; Path=/", "Content-Type": "application/json"], "{}"),
        ])
        try await server.start()
        return server
    }

    @Test("Same-origin redirects are followed; cross-origin ones are not")
    func redirects() async throws {
        let server = try await server()
        defer { server.stop() }
        let http = HTTPClient(transport: URLSessionTransport())
        let base = "http://127.0.0.1:\(server.port)"

        let followed = try await http.getJSON(URL(string: "\(base)/same-origin")!, bearer: "token-1")
        #expect(followed == ["ok": true])

        let error = await expectNineError(.requestFailed) { _ = try await http.getJSON(URL(string: "\(base)/cross-origin")!, bearer: "token-2") }
        #expect(error?.status == 302)
        // localhost (another origin) never saw the request or the token.
        #expect(server.seen.current.map(\.path) == ["/same-origin", "/json", "/cross-origin"])
        #expect(server.seen.current.allSatisfy { $0.headers["host"]?.hasPrefix("127.0.0.1") == true })
    }

    @Test("OAuth error bodies become NineError with status; other failures too")
    func errors() async throws {
        let server = try await server()
        defer { server.stop() }
        let http = HTTPClient(transport: URLSessionTransport())
        let base = "http://127.0.0.1:\(server.port)"
        let oauth = await expectNineError("invalid_request") { _ = try await http.postForm(URL(string: "\(base)/oauth-error")!, [("a", "b")]) }
        #expect(oauth?.message == "bad input")
        #expect(oauth?.status == 400)
        let plain = await expectNineError(.requestFailed) { _ = try await http.getJSON(URL(string: "\(base)/plain-error")!) }
        #expect(plain?.message == "HTTP 500")
        await expectNineError(.invalidResponse) { _ = try await http.getJSON(URL(string: "\(base)/not-json")!) }
    }

    @Test("No cookies are kept or sent")
    func cookies() async throws {
        let server = try await server()
        defer { server.stop() }
        let http = HTTPClient(transport: URLSessionTransport())
        let base = "http://127.0.0.1:\(server.port)"
        _ = try await http.getJSON(URL(string: "\(base)/cookie")!)
        _ = try await http.getJSON(URL(string: "\(base)/json")!)
        #expect(server.seen.current.last?.headers["cookie"] == nil)
    }

    @Test("Forms are posted as application/x-www-form-urlencoded with Accept: application/json")
    func formPost() async throws {
        let server = try await server()
        defer { server.stop() }
        let http = HTTPClient(transport: URLSessionTransport())
        _ = try await http.postForm(URL(string: "http://127.0.0.1:\(server.port)/json")!, [("grant_type", "refresh_token")])
        let seen = try #require(server.seen.current.last)
        #expect(seen.headers["content-type"] == "application/x-www-form-urlencoded")
        #expect(seen.headers["accept"] == "application/json")
    }

    @Test("Unreachable hosts are network_error")
    func unreachable() async throws {
        let http = HTTPClient(transport: URLSessionTransport(timeout: 2))
        // Port 9 on loopback: nothing listens there.
        await expectNineError(.networkError) { _ = try await http.getJSON(URL(string: "http://127.0.0.1:9/x")!) }
    }

    @Test("Origins")
    func origins() {
        let same = SameOriginRedirects.sameOrigin
        #expect(same(URL(string: "https://a.com/x")!, URL(string: "https://A.com:443/y")!))
        #expect(!same(URL(string: "https://a.com/x")!, URL(string: "http://a.com/x")!))
        #expect(!same(URL(string: "https://a.com/x")!, URL(string: "https://b.com/x")!))
        #expect(!same(URL(string: "https://a.com/x")!, URL(string: "https://a.com:8443/x")!))
    }
}
