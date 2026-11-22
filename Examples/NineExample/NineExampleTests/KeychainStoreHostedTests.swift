import Nine
import Security
import XCTest

/// The default Keychain store, inside a real iOS app (this bundle is hosted by NineExample).
/// The package's own tests skip these on the iOS Simulator: a package test bundle has no app
/// host, so no Keychain entitlement.
final class KeychainStoreHostedTests: XCTestCase {
    private var store: KeychainCredentialStore!

    override func setUp() {
        store = KeychainCredentialStore(service: "io.9in.nine.hosted-tests.\(UUID().uuidString)")
    }

    override func tearDown() {
        try? store.delete("a")
        try? store.delete("b")
    }

    func testWriteReadReplaceDelete() throws {
        XCTAssertNil(try store.read("a"))
        try store.write(Data("one".utf8), for: "a")
        XCTAssertEqual(try store.read("a"), Data("one".utf8))
        try store.write(Data("two".utf8), for: "a")
        XCTAssertEqual(try store.read("a"), Data("two".utf8))
        try store.write(Data("bee".utf8), for: "b")
        XCTAssertEqual(try store.read("b"), Data("bee".utf8))
        try store.delete("a")
        XCTAssertNil(try store.read("a"))
        XCTAssertEqual(try store.read("b"), Data("bee".utf8))
        try store.delete("a") // nothing to delete is fine
    }

    func testServicesAreSeparate() throws {
        let other = KeychainCredentialStore(service: store.service + ".other")
        try store.write(Data("x".utf8), for: "a")
        XCTAssertNil(try other.read("a"))
        try other.delete("a")
        XCTAssertEqual(try store.read("a"), Data("x".utf8))
    }

    func testItemIsThisDeviceOnlyAfterFirstUnlock() throws {
        try store.write(Data("x".utf8), for: "a")
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: store.service,
            kSecAttrAccount: "a",
            kSecReturnAttributes: true,
        ]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)
        let attributes = try XCTUnwrap(result as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
    }

    func testOtherAccessibilityClasses() throws {
        let unlocked = KeychainCredentialStore(service: store.service, accessibility: .whenUnlockedThisDeviceOnly)
        try unlocked.write(Data("y".utf8), for: "b")
        XCTAssertEqual(try store.read("b"), Data("y".utf8))
    }

    func testClientFindsNothingInAnEmptyKeychainSlot() {
        let nine = NineClient(configuration: .init(issuer: "https://acme.9in.io", clientId: "app_hosted", redirectURI: "io.ninein.example:/callback"), store: store)
        XCTAssertFalse(nine.isSignedIn)
        XCTAssertNil(nine.user)
    }
}
