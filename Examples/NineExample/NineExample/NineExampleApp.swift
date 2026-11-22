import Nine
import SwiftUI

@main
struct NineExampleApp: App {
    // One client for the whole app. It keeps the session in the Keychain and refreshes tokens.
    @StateObject private var nine = NineClient(configuration: Config.configuration, store: Config.store)

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(nine)
        }
    }
}
