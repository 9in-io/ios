import XCTest

/// Runs the example app against `MockIssuer` through the real system browser sheet
/// (ASWebAuthenticationSession): sign-in, userinfo, refresh, a relaunch that finds the session
/// in the Keychain, and sign-out.
final class NineExampleUITests: XCTestCase {
    private var issuer: MockIssuer!

    override func setUpWithError() throws {
        continueAfterFailure = false
        issuer = try MockIssuer()
        try issuer.start()
    }

    override func tearDown() {
        issuer?.stop()
    }

    @MainActor
    private func launch(_ extra: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = [
            "-NineIssuer", issuer.issuer,
            "-NineClientId", issuer.clientId,
            "-NineRedirectURI", "io.ninein.example:/callback",
            "-NineKeychainService", "io.9in.nine.uitests.\(name.hashValue)",
        ] + extra
        app.launch()
        return app
    }

    /// The "“NineExample” Wants to Use … to Sign In" alert of a shared (non-ephemeral) session.
    @MainActor
    private func allowSignInPrompt() {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let allow = springboard.buttons["Continue"]
        if allow.waitForExistence(timeout: 10) { allow.tap() }
    }

    @MainActor
    func testPrivateSessionSignInUserinfoRelaunchAndSignOut() throws {
        var app = launch(["-NineEphemeral", "YES"])
        app.buttons["signIn"].tap()

        XCTAssertTrue(app.staticTexts["email"].waitForExistence(timeout: 30), "signed in")
        XCTAssertEqual(app.staticTexts["email"].label, issuer.email)

        app.buttons["userinfo"].tap()
        XCTAssertTrue(app.staticTexts["result"].waitForExistence(timeout: 15))
        XCTAssertEqual(app.staticTexts["result"].label, "userinfo: \(issuer.email)")

        app.buttons["refresh"].tap()
        let refreshed = NSPredicate(format: "label BEGINSWITH 'Access token valid until'")
        expectation(for: refreshed, evaluatedWith: app.staticTexts["result"])
        waitForExpectations(timeout: 15)

        // The session is in the Keychain: a relaunch is still signed in.
        app.terminate()
        app = launch(["-NineEphemeral", "YES"])
        XCTAssertTrue(app.staticTexts["email"].waitForExistence(timeout: 15), "still signed in after a relaunch")

        // A private session has nothing to end in the browser: sign-out stays in the app.
        app.buttons["signOut"].tap()
        XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 15), "signed out")
        app.terminate()
        app = launch(["-NineEphemeral", "YES"])
        XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 15), "still signed out after a relaunch")

        let requests = issuer.requests
        XCTAssertTrue(requests.contains("GET /oauth/authorize"))
        XCTAssertEqual(requests.filter { $0 == "POST /oauth/token" }.count, 2) // code exchange, refresh
        XCTAssertTrue(requests.contains("POST /oauth/revoke"))
        XCTAssertFalse(requests.contains("GET /oauth/logout"))
    }

    @MainActor
    func testSharedSessionSignInAndSignOutInTheBrowser() throws {
        let app = launch(["-NinePostLogoutRedirectURI", "io.ninein.example:/signed-out"])
        app.buttons["signIn"].tap()
        allowSignInPrompt()
        XCTAssertTrue(app.staticTexts["email"].waitForExistence(timeout: 30), "signed in")

        app.buttons["signOut"].tap()
        allowSignInPrompt()
        XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 30), "signed out")
        XCTAssertTrue(issuer.requests.contains("GET /oauth/logout"), "the 9in session was ended in the browser")
        XCTAssertFalse(app.staticTexts["error"].exists)
    }

    /// Opt-in: the example against a real tenant opens 9in's hosted page in the system browser
    /// sheet. Run with TEST_RUNNER_NINE_LIVE_ISSUER and TEST_RUNNER_NINE_LIVE_CLIENT_ID set (and
    /// TEST_RUNNER_NINE_LIVE_REDIRECT_URI unless io.ninein.example:/callback is registered).
    @MainActor
    func testOpensTheHostedLoginPage() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let issuer = environment["NINE_LIVE_ISSUER"], let clientId = environment["NINE_LIVE_CLIENT_ID"] else {
            throw XCTSkip("set TEST_RUNNER_NINE_LIVE_ISSUER and TEST_RUNNER_NINE_LIVE_CLIENT_ID to run against a real tenant")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-NineIssuer", issuer, "-NineClientId", clientId,
                               "-NineRedirectURI", environment["NINE_LIVE_REDIRECT_URI"] ?? "io.ninein.example:/callback",
                               "-NineKeychainService", "io.9in.nine.uitests.live"]
        app.launch()
        app.buttons["signIn"].tap()
        allowSignInPrompt()
        // The sheet's view tree belongs to SafariViewService or Safari, depending on the OS.
        let browsers = ["com.apple.SafariViewService", "com.apple.mobilesafari"].map { XCUIApplication(bundleIdentifier: $0) }
        var sheet: XCUIApplication?
        for _ in 0..<30 where sheet == nil {
            sheet = browsers.first { $0.buttons["URL"].exists || $0.webViews.firstMatch.exists }
            if sheet == nil { sleep(1) }
        }
        let browser = try XCTUnwrap(sheet, "the system browser sheet opened")
        _ = browser.webViews.firstMatch.staticTexts.firstMatch.waitForExistence(timeout: 30) // let the page render
        sleep(2)
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = "hosted-page"
        shot.lifetime = .keepAlways
        add(shot)
        let address = browser.buttons["URL"].exists ? "\(browser.buttons["URL"].value ?? "")" : ""
        let text = browser.webViews.firstMatch.staticTexts.allElementsBoundByIndex.prefix(40).map(\.label).joined(separator: " | ")
        let page = XCTAttachment(string: "address: \(address)\ntext: \(text)")
        page.name = "hosted-page-text"
        page.lifetime = .keepAlways
        add(page)
        XCTAssertFalse(app.staticTexts["error"].exists, "the app showed no error")
    }
}
