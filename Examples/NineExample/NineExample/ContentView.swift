import Nine
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var nine: NineClient
    @State private var result: String?
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationView {
            List {
                if let user = nine.user {
                    Section("Signed in") {
                        row("Name", user.name ?? "—")
                        row("Email", user.email ?? "—", id: "email")
                        row("User ID", user.sub)
                        row("Signed in with", user.amr.joined(separator: ", "))
                    }
                    Section {
                        Button("Call userinfo") {
                            run { result = "userinfo: \(try await nine.userInfo().email ?? "?")" }
                        }
                        .accessibilityIdentifier("userinfo")
                        Button("Refresh tokens") {
                            run {
                                let tokens = try await nine.refresh()
                                result = "Access token valid until \(tokens.expiresAt.formatted(date: .omitted, time: .standard))"
                            }
                        }
                        .accessibilityIdentifier("refresh")
                        Button("Sign out", role: .destructive) {
                            run {
                                result = nil
                                try await nine.signOut()
                            }
                        }
                        .accessibilityIdentifier("signOut")
                    }
                } else {
                    Section {
                        Text("Sign in on your 9in tenant's hosted login page, in the system browser.")
                            .foregroundColor(.secondary)
                        Button("Sign in") { run { try await nine.signIn() } }
                            .accessibilityIdentifier("signIn")
                        Button("Create an account") { run { try await nine.signUp() } }
                            .accessibilityIdentifier("signUp")
                    }
                }
                if let result {
                    Section("Result") {
                        Text(result).font(.footnote).accessibilityIdentifier("result")
                    }
                }
                if let error {
                    Section("Error") {
                        Text(error).foregroundColor(.red).accessibilityIdentifier("error")
                    }
                }
            }
            .navigationTitle("9in example")
        }
        .navigationViewStyle(.stack)
        .disabled(busy)
    }

    private func row(_ label: String, _ value: String, id: String? = nil) -> some View {
        HStack {
            Text(label).foregroundColor(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing).accessibilityIdentifier(id ?? label)
        }
    }

    private func run(_ action: @escaping @MainActor () async throws -> Void) {
        Task {
            busy = true
            defer { busy = false }
            error = nil
            do {
                try await action()
            } catch let failure as NineError where failure.code == .canceled {
                // The user closed the sheet: nothing to show.
            } catch {
                self.error = String(describing: error)
            }
        }
    }
}
