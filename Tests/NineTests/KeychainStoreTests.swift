import Foundation
import Security
import Testing
@testable import Nine

@Suite("Keychain credential store", .serialized)
struct KeychainStoreTests {
    private func withStore(_ body: (KeychainCredentialStore) async throws -> Void) async throws {
        let store = KeychainCredentialStore(service: "io.9in.nine.tests.\(UUID().uuidString)")
        defer {
            try? store.delete("a")
            try? store.delete("b")
            try? store.delete("https://acme.9in.test app_test")
        }
        try await body(store)
    }

    @Test("Write, read, replace and delete")
    func roundTrip() async throws {
        try await withStore { store in
            #expect(try store.read("a") == nil)
            try store.write(Data("one".utf8), for: "a")
            #expect(try store.read("a") == Data("one".utf8))
            try store.write(Data("two".utf8), for: "a")
            #expect(try store.read("a") == Data("two".utf8))
            try store.write(Data("bee".utf8), for: "b")
            #expect(try store.read("a") == Data("two".utf8))
            #expect(try store.read("b") == Data("bee".utf8))
            try store.delete("a")
            #expect(try store.read("a") == nil)
            #expect(try store.read("b") == Data("bee".utf8))
            try store.delete("a") // nothing to delete is fine
        }
    }

    @Test("Services don't see each other's items")
    func isolation() async throws {
        try await withStore { store in
            let other = KeychainCredentialStore(service: store.service + ".other")
            try store.write(Data("x".utf8), for: "a")
            #expect(try other.read("a") == nil)
            try other.delete("a")
            #expect(try store.read("a") == Data("x".utf8))
        }
    }

    @Test("The item is this-device-only and readable after the first unlock")
    func attributes() async throws {
        try await withStore { store in
            try store.write(Data("x".utf8), for: "a")
            #expect(store.accessibility == .afterFirstUnlockThisDeviceOnly)
            var query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: store.service,
                kSecAttrAccount: "a",
                kSecReturnAttributes: true,
            ]
            #if os(macOS)
            // The data protection keychain when the test runner may use it, the login keychain otherwise.
            var result: CFTypeRef?
            query[kSecUseDataProtectionKeychain] = true
            if SecItemCopyMatching(query as CFDictionary, &result) != errSecSuccess {
                query[kSecUseDataProtectionKeychain] = nil
                #expect(SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess)
                return // the login keychain has no accessibility classes
            }
            #else
            var result: CFTypeRef?
            #expect(SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess)
            #endif
            let attributes = try #require(result as? [String: Any])
            #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        }
    }

    @Test("A NineClient keeps its session in the Keychain")
    func client() async throws {
        try await withStore { store in
            let fake = FakeNine()
            let nine = fake.client(store: store)
            let user = try await nine.signIn()
            #expect(try store.read("\(fake.issuer) \(fake.clientId)") != nil)
            let again = fake.client(store: store)
            #expect(again.user == user)
            fake.clock.advance(3600)
            _ = try await again.accessToken()
            #expect(fake.client(store: store).tokens?.refreshToken == again.tokens?.refreshToken)
            try await again.signOut(endSession: false)
            #expect(try store.read("\(fake.issuer) \(fake.clientId)") == nil)
            #expect(!fake.client(store: store).isSignedIn)
        }
    }
}
