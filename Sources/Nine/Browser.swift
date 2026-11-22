import Foundation
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// Shows 9in's hosted pages to the user. The default, `SystemBrowser`, uses
/// `ASWebAuthenticationSession` (the system browser, never a web view). Tests and other
/// platforms can bring their own.
public protocol Browser: Sendable {
    /// Shows `url` and returns the URL the browser was sent to when it reached `callbackURL`
    /// (same scheme, host and path; the query carries the result). Throws
    /// `NineError(.canceled)` when the user closes it.
    ///
    /// - Parameter ephemeral: don't share cookies with the user's browser (no single sign-on).
    func open(_ url: URL, callbackURL: URL, ephemeral: Bool) async throws -> URL
}

/// How a browser session recognises the end of the flow, from the redirect URI.
enum CallbackMatch: Equatable {
    /// A custom scheme such as `com.acme.app:/callback`.
    case customScheme(String)
    /// A universal link such as `https://app.acme.com/callback`.
    case https(host: String, path: String)
    /// `http://127.0.0.1:…`: only for browsers that can listen on a loopback port.
    case loopback

    init(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased() else {
            throw NineError(.invalidOptions, "the redirect URI needs a scheme")
        }
        switch scheme {
        case "https":
            guard let host = url.host, !host.isEmpty else { throw NineError(.invalidOptions, "the redirect URI has no host") }
            self = .https(host: host, path: url.path.isEmpty ? "/" : url.path)
        case "http":
            guard let host = url.host, Issuer.isLocal(host) else {
                throw NineError(.invalidOptions, "an http redirect URI must be a loopback address")
            }
            self = .loopback
        default:
            self = .customScheme(scheme)
        }
    }
}

/// Whether `url` is where the browser was sent back to: the redirect URI's scheme, host and path.
func matchesCallback(_ url: URL, _ callback: URL) -> Bool {
    func normalizedPath(_ url: URL) -> String {
        // `com.acme.app:/callback` and `com.acme.app:///callback` both have path /callback.
        let path = URLComponents(url: url, resolvingAgainstBaseURL: false)?.path ?? url.path
        return path.isEmpty ? "/" : path
    }
    return url.scheme?.lowercased() == callback.scheme?.lowercased()
        && (url.host ?? "").lowercased() == (callback.host ?? "").lowercased()
        && url.port == callback.port
        && normalizedPath(url) == normalizedPath(callback)
}

#if canImport(AuthenticationServices) && !os(tvOS) && !os(watchOS)

/// The system browser sheet (`ASWebAuthenticationSession`). Redirect URIs with a custom scheme
/// work everywhere; universal links (`https://`) need iOS 17.4 / macOS 14.4 and the
/// `webcredentials` associated domain.
public struct SystemBrowser: Browser {
    /// Returns the window the sheet is presented over.
    public typealias PresentationAnchor = @MainActor @Sendable () -> ASPresentationAnchor

    private let anchor: PresentationAnchor?

    /// - Parameter presentationAnchor: the window to present over; by default the key window
    ///   of the app's active scene.
    public init(presentationAnchor: PresentationAnchor? = nil) {
        anchor = presentationAnchor
    }

    public func open(_ url: URL, callbackURL: URL, ephemeral: Bool) async throws -> URL {
        let match = try CallbackMatch(callbackURL)
        return try await present(url, match: match, ephemeral: ephemeral)
    }

    @MainActor
    private func present(_ url: URL, match: CallbackMatch, ephemeral: Bool) async throws -> URL {
        let presenter = SessionPresenter(anchor: anchor)
        return try await withTaskCancellationHandler {
            try await presenter.start(url, match: match, ephemeral: ephemeral)
        } onCancel: {
            Task { @MainActor in presenter.cancel() }
        }
    }
}

/// Keeps the session alive while it is shown and resumes the caller exactly once.
@MainActor
private final class SessionPresenter: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchor: SystemBrowser.PresentationAnchor?
    private var session: ASWebAuthenticationSession?
    private var continuation: CheckedContinuation<URL, Error>?

    init(anchor: SystemBrowser.PresentationAnchor?) {
        self.anchor = anchor
    }

    func start(_ url: URL, match: CallbackMatch, ephemeral: Bool) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let completion: @Sendable (URL?, Error?) -> Void = { [weak self] callback, error in
                Task { @MainActor in self?.finish(callback, error) }
            }
            let session: ASWebAuthenticationSession
            switch match {
            case let .customScheme(scheme):
                if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
                    session = ASWebAuthenticationSession(url: url, callback: .customScheme(scheme), completionHandler: completion)
                } else {
                    session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
                }
            case let .https(host, path):
                if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
                    session = ASWebAuthenticationSession(url: url, callback: .https(host: host, path: path), completionHandler: completion)
                } else {
                    finish(nil, NineError(.invalidOptions, "https redirect URIs need iOS 17.4 or macOS 14.4; use a custom scheme"))
                    return
                }
            case .loopback:
                finish(nil, NineError(.invalidOptions, "the system browser can't return to an http://127.0.0.1 redirect URI; use a custom scheme"))
                return
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = ephemeral
            self.session = session
            if !session.start() {
                finish(nil, NineError(.browserFailed, "the sign-in sheet could not be shown"))
            }
        }
    }

    func cancel() {
        session?.cancel()
        finish(nil, CancellationError())
    }

    private func finish(_ callback: URL?, _ error: Error?) {
        guard let continuation else { return }
        self.continuation = nil
        session = nil
        if let callback {
            continuation.resume(returning: callback)
        } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
            continuation.resume(throwing: NineError(.canceled, "the user closed the sign-in sheet"))
        } else if let error = error as? NineError {
            continuation.resume(throwing: error)
        } else if error is CancellationError {
            continuation.resume(throwing: CancellationError())
        } else {
            continuation.resume(throwing: NineError(.browserFailed, error?.localizedDescription ?? "the browser returned nothing"))
        }
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            if let anchor { return anchor() }
            return Self.defaultAnchor()
        }
    }

    private static func defaultAnchor() -> ASPresentationAnchor {
        #if canImport(UIKit)
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let active = scenes.filter { $0.activationState == .foregroundActive } + scenes
        for scene in active {
            if let window = scene.keyWindow ?? scene.windows.first { return window }
        }
        return ASPresentationAnchor()
        #else
        return NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #endif
    }
}

#endif
