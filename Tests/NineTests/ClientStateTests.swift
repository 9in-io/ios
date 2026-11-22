import Combine
import Foundation
#if canImport(Observation)
import Observation
#endif
import Testing
@testable import Nine

/// A store whose reads can fail, like the Keychain before the first unlock.
final class FlakyStore: CredentialStore, @unchecked Sendable {
    let inner = MemoryCredentialStore()
    let failReads = Locked(false)
    let failWrites = Locked(false)
    let failDeletes = Locked(false)

    func read(_ key: String) throws -> Data? {
        if failReads.current { throw NineError(.keychainError, "locked") }
        return try inner.read(key)
    }

    func write(_ data: Data, for key: String) throws {
        if failWrites.current { throw NineError(.keychainError, "full") }
        try inner.write(data, for: key)
    }

    func delete(_ key: String) throws {
        if failDeletes.current { throw NineError(.keychainError, "refused") }
        try inner.delete(key)
    }
}

@Suite("Client state: persistence, SwiftUI observation, stores")
struct ClientStateTests {
    @Test("A new client finds the saved session at once")
    func persistence() async throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        let first = fake.client(store: store)
        let user = try await first.signIn()
        let second = fake.client(store: store)
        #expect(second.isSignedIn)
        #expect(second.user == user)
        #expect(second.tokens == first.tokens)
        _ = try await second.accessToken()
        // Another client ID or issuer has its own slot.
        #expect(!fake.client(store: store, configure: { $0.clientId = "other" }).isSignedIn)
    }

    @Test("Unreadable saved data counts as signed out")
    func corrupt() throws {
        let fake = FakeNine()
        let store = MemoryCredentialStore()
        try store.write(Data("garbage".utf8), for: "\(fake.issuer) \(fake.clientId)")
        #expect(!fake.client(store: store).isSignedIn)
    }

    @Test("A store that can't be read at launch is read again later")
    func lockedAtLaunch() async throws {
        let fake = FakeNine()
        let store = FlakyStore()
        try await fake.client(store: store).signIn()
        store.failReads.withLock { $0 = true }
        let nine = fake.client(store: store)
        #expect(!nine.isSignedIn)
        await expectNineError(.keychainError) { _ = try await nine.accessToken() }
        store.failReads.withLock { $0 = false }
        _ = try await nine.accessToken()
        #expect(nine.isSignedIn)
        #expect(nine.user?.email == "jane@example.com")
    }

    @Test("A failing save fails the sign-in; a failing delete fails the sign-out but signs out")
    func storeFailures() async throws {
        let fake = FakeNine()
        let store = FlakyStore()
        let nine = fake.client(store: store)
        store.failWrites.withLock { $0 = true }
        await expectNineError(.keychainError) { try await nine.signIn() }
        #expect(!nine.isSignedIn)
        store.failWrites.withLock { $0 = false }
        try await nine.signIn()
        // A refresh whose save fails still hands out the new token.
        store.failWrites.withLock { $0 = true }
        let refreshed = try await nine.refresh()
        #expect(nine.tokens == refreshed)
        store.failWrites.withLock { $0 = false }
        store.failDeletes.withLock { $0 = true }
        await expectNineError(.keychainError) { try await nine.signOut(endSession: false) }
        #expect(!nine.isSignedIn)
        #expect(fake.requests("/oauth/revoke").count == 1, "revoked, so the tokens left in the store are dead")
    }

    @Test("objectWillChange fires on the main actor at sign-in and sign-out")
    func objectWillChange() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        let events = Locked<[Bool]>([])
        let subscription = nine.objectWillChange.sink { _ in events.withLock { $0.append(Thread.isMainThread) } }
        defer { subscription.cancel() }
        try await nine.signIn()
        #expect(nine.isSignedIn) // already true when signIn returns
        try await nine.signOut(endSession: false)
        #expect(!nine.isSignedIn)
        #expect(events.current == [true, true])
    }

    @Test("Observation (iOS 17+ / macOS 14+) sees user and isSignedIn change")
    func observation() async throws {
        guard #available(iOS 17.0, macOS 14.0, *) else { return }
        let fake = FakeNine()
        let nine = fake.client()
        let changed = Locked(0)
        withObservationTracking {
            _ = nine.user
            _ = nine.isSignedIn
        } onChange: {
            changed.withLock { $0 += 1 }
        }
        try await nine.signIn()
        #expect(changed.current == 1)

        withObservationTracking { _ = nine.tokens } onChange: { changed.withLock { $0 += 1 } }
        try await nine.refresh()
        #expect(changed.current == 2)
    }

    @Test("Dumping a client never shows its tokens")
    func mirror() async throws {
        let fake = FakeNine()
        let nine = fake.client()
        try await nine.signIn()
        var dumped = ""
        dump(nine, to: &dumped)
        let tokens = try #require(nine.tokens)
        let leaks = [tokens.accessToken, tokens.refreshToken!, tokens.idToken!].contains { dumped.contains($0) }
        #expect(!leaks)
        #expect(dumped.contains("usr_8k2"))
    }

    @Test("Memory store: write, read, replace, delete")
    func memoryStore() throws {
        let store = MemoryCredentialStore()
        #expect(try store.read("k") == nil)
        try store.write(Data("1".utf8), for: "k")
        try store.write(Data("2".utf8), for: "k")
        #expect(try store.read("k") == Data("2".utf8))
        try store.delete("k")
        try store.delete("k")
        #expect(try store.read("k") == nil)
    }
}
