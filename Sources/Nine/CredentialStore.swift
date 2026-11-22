import Foundation
import Security

/// Where `NineClient` keeps the signed-in user's tokens between launches. The default is
/// `KeychainCredentialStore`. Implement this to keep them elsewhere; calls come from any thread.
public protocol CredentialStore: Sendable {
    /// The data saved under `key`, or nil.
    func read(_ key: String) throws -> Data?
    /// Saves `data` under `key`, replacing what was there.
    func write(_ data: Data, for key: String) throws
    /// Removes what is saved under `key` (nothing to remove is not an error).
    func delete(_ key: String) throws
}

/// Keeps tokens in the Keychain as generic passwords, readable after the first unlock and never
/// synced or restored to another device (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
public final class KeychainCredentialStore: CredentialStore, @unchecked Sendable {
    /// When the item can be read.
    public struct Accessibility: Sendable, Hashable {
        let value: String

        /// After the first unlock since restart, this device only (the default: background
        /// refreshes work, the item is never in backups restored elsewhere).
        public static let afterFirstUnlockThisDeviceOnly = Accessibility(value: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        /// While the device is unlocked, this device only.
        public static let whenUnlockedThisDeviceOnly = Accessibility(value: kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        /// After the first unlock; may move to a new device with an encrypted backup.
        public static let afterFirstUnlock = Accessibility(value: kSecAttrAccessibleAfterFirstUnlock as String)
        /// While unlocked; may move to a new device with an encrypted backup.
        public static let whenUnlocked = Accessibility(value: kSecAttrAccessibleWhenUnlocked as String)
    }

    public let service: String
    public let accessGroup: String?
    public let accessibility: Accessibility
    #if os(macOS)
    /// macOS: the data protection keychain (like iOS) when the app is signed with a team (it has
    /// an application identifier); the login keychain when it isn't (command-line tools, tests,
    /// unsigned builds), which is all those can use.
    private let dataProtection = Locked(KeychainCredentialStore.hasApplicationIdentifier)

    private static let hasApplicationIdentifier: Bool = {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        return ["com.apple.application-identifier", "application-identifier", "keychain-access-groups"].contains { name in
            SecTaskCopyValueForEntitlement(task, name as CFString, nil) != nil
        }
    }()
    #endif

    /// - Parameters:
    ///   - service: `kSecAttrService` of the items.
    ///   - accessGroup: a Keychain access group, to share the tokens with your other apps or extensions.
    ///   - accessibility: when the tokens can be read.
    public init(service: String = "io.9in.nine", accessGroup: String? = nil, accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessibility = accessibility
    }

    private func query(_ key: String, dataProtection: Bool) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        #if os(macOS)
        if dataProtection { query[kSecUseDataProtectionKeychain] = true }
        #endif
        return query
    }

    /// Runs `body` against the data protection keychain, or on macOS the login keychain when the
    /// process has no entitlement for the former.
    private func perform(_ body: (_ dataProtection: Bool) -> OSStatus) -> OSStatus {
        #if os(macOS)
        guard dataProtection.current else { return body(false) }
        let status = body(true)
        guard status == errSecMissingEntitlement else { return status }
        dataProtection.withLock { $0 = false }
        return body(false)
        #else
        return body(true)
        #endif
    }

    public func read(_ key: String) throws -> Data? {
        var result: CFTypeRef?
        let status = perform { dataProtection in
            var query = self.query(key, dataProtection: dataProtection)
            query[kSecReturnData] = true
            query[kSecMatchLimit] = kSecMatchLimitOne
            result = nil
            return SecItemCopyMatching(query as CFDictionary, &result)
        }
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw Self.error(status, "read")
        }
    }

    public func write(_ data: Data, for key: String) throws {
        let status = perform { dataProtection in
            let query = self.query(key, dataProtection: dataProtection)
            let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: self.accessibility.value]
            let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            guard updated == errSecItemNotFound else { return updated }
            var item = query
            item[kSecValueData] = data
            item[kSecAttrAccessible] = self.accessibility.value
            return SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Self.error(status, "write") }
    }

    public func delete(_ key: String) throws {
        let status = perform { dataProtection in
            SecItemDelete(self.query(key, dataProtection: dataProtection) as CFDictionary)
        }
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.error(status, "delete") }
    }

    private static func error(_ status: OSStatus, _ operation: String) -> NineError {
        let detail = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
        return NineError(.keychainError, "could not \(operation) the Keychain item: \(detail) (\(status))")
    }
}

/// Keeps tokens in memory only: the user is signed out when the app quits. For previews and tests.
public final class MemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private let items = Locked<[String: Data]>([:])

    public init() {}

    public func read(_ key: String) throws -> Data? { items.withLock { $0[key] } }
    public func write(_ data: Data, for key: String) throws { items.withLock { $0[key] = data } }
    public func delete(_ key: String) throws { _ = items.withLock { $0.removeValue(forKey: key) } }
}
