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

    // MARK: Live, against a real tenant (opt-in)

    /// The settings of the live tests, from the environment (`TEST_RUNNER_NINE_LIVE_*` when run by
    /// xcodebuild; `live-ui-tests.sh` sets them from the e2e settings file).
    private func live() throws -> (issuer: String, clientId: String, redirectURI: String) {
        let environment = ProcessInfo.processInfo.environment
        guard let issuer = environment["NINE_LIVE_ISSUER"], let clientId = environment["NINE_LIVE_CLIENT_ID"] else {
            throw XCTSkip("set TEST_RUNNER_NINE_LIVE_ISSUER and TEST_RUNNER_NINE_LIVE_CLIENT_ID (see live-ui-tests.sh)")
        }
        return (issuer, clientId, environment["NINE_LIVE_REDIRECT_URI"] ?? "io.ninein.example:/callback")
    }

    @MainActor
    private func launchLive(_ settings: (issuer: String, clientId: String, redirectURI: String), keychain: String, ephemeral: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-NineIssuer", settings.issuer, "-NineClientId", settings.clientId,
                               "-NineRedirectURI", settings.redirectURI,
                               "-NinePostLogoutRedirectURI", "io.ninein.example:/signed-out",
                               "-NineKeychainService", keychain, "-NineEphemeral", ephemeral ? "YES" : "NO"]
        app.launch()
        return app
    }

    /// The system browser sheet: its view tree belongs to SafariViewService or Safari, depending on the OS.
    @MainActor
    private func systemBrowser(timeout: Int = 30) -> XCUIApplication? {
        let browsers = ["com.apple.SafariViewService", "com.apple.mobilesafari"].map { XCUIApplication(bundleIdentifier: $0) }
        for _ in 0..<timeout {
            if let found = browsers.first(where: { $0.buttons["URL"].exists || $0.webViews.firstMatch.exists }) { return found }
            sleep(1)
        }
        return nil
    }

    /// The hosted sign-in form in the sheet: its email field, once the page has rendered.
    @MainActor
    private func signInForm(_ browser: XCUIApplication) -> XCUIElement {
        let web = browser.webViews.firstMatch
        let labelled = web.textFields["Email"]
        return labelled.waitForExistence(timeout: 30) ? labelled : web.textFields.firstMatch
    }

    /// Types into a web form field, tapping until it has the keyboard focus (in the sheet, a field
    /// tapped while the previous one's keyboard settles may not take it).
    @MainActor
    private func type(_ text: String, into field: XCUIElement, label: String, in browser: XCUIApplication) {
        let web = browser.webViews.firstMatch
        func focused() -> Bool { (field.value(forKey: "hasKeyboardFocus") as? Bool) == true }
        for attempt in 0..<6 {
            switch attempt % 3 {
            case 0: field.tap()
            case 1: web.staticTexts[label].firstMatch.tap() // <label for=…> focuses its input
            default:
                web.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.05)).tap() // blur, then try again
                field.tap()
            }
            if focused() { break }
            sleep(1)
        }
        if !focused() { screenshot("no-focus-\(label)") }
        field.typeText(text)
    }

    @MainActor
    private func screenshot(_ name: String) {
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }

    /// The example against the real tenant opens 9in's sign-in form in the system browser sheet;
    /// closing the sheet is not an error.
    @MainActor
    func testOpensTheHostedLoginPage() throws {
        let settings = try live()
        // A private session: whatever 9in session Safari has, the form shows.
        let app = launchLive(settings, keychain: "io.9in.nine.uitests.live-page.\(UUID().uuidString)", ephemeral: true)
        app.buttons["signIn"].tap()
        let browser = try XCTUnwrap(systemBrowser(), "the system browser sheet opened")
        let email = signInForm(browser)
        XCTAssertTrue(email.exists, "the sheet shows 9in's sign-in form")
        XCTAssertTrue(browser.webViews.firstMatch.secureTextFields.firstMatch.exists, "with a password field")
        screenshot("hosted-page")
        browser.buttons["Close"].firstMatch.tap() // the sheet's Cancel
        XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 15))
        XCTAssertFalse(app.staticTexts["error"].exists, "closing the sheet is not an error")
    }

    /// A full sign-in against the real tenant through the system browser sheet: the form filled in
    /// with a sandbox user, the user shown, userinfo and a token refresh against 9in, a relaunch that
    /// is still signed in, sign-out that ends the 9in session, and a new sign-in that asks again.
    @MainActor
    func testLiveSignInEndToEnd() throws {
        let settings = try live()
        guard let address = ProcessInfo.processInfo.environment["NINE_LIVE_EMAIL"] else {
            throw XCTSkip("set TEST_RUNNER_NINE_LIVE_EMAIL to a sandbox address (live-ui-tests.sh does, and deletes the user)")
        }
        let keychain = "io.9in.nine.uitests.live-e2e.\(address)"
        var app = launchLive(settings, keychain: keychain)
        if app.buttons["signOut"].waitForExistence(timeout: 3) { // left over from an interrupted run
            app.buttons["signOut"].tap()
            allowSignInPrompt()
        }

        app.buttons["signIn"].tap()
        allowSignInPrompt()
        var browser = try XCTUnwrap(systemBrowser(), "the system browser sheet opened")
        var email = signInForm(browser)
        if !email.exists, app.staticTexts["email"].waitForExistence(timeout: 10) {
            // Safari still had a 9in session from an earlier run (single sign-on): end it, start again.
            app.buttons["signOut"].tap()
            allowSignInPrompt()
            XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 30))
            app.buttons["signIn"].tap()
            allowSignInPrompt()
            browser = try XCTUnwrap(systemBrowser(), "the system browser sheet opened")
            email = signInForm(browser)
        }
        XCTAssertTrue(email.exists, "the sheet shows 9in's sign-in form")
        type(address, into: email, label: "Email", in: browser)
        type("any-password-1", into: browser.webViews.firstMatch.secureTextFields.firstMatch, label: "Password", in: browser)
        screenshot("filled-in")
        browser.webViews.firstMatch.buttons["Sign in"].tap()

        XCTAssertTrue(app.staticTexts["email"].waitForExistence(timeout: 60), "signed in")
        XCTAssertEqual(app.staticTexts["email"].label, address)
        XCTAssertTrue(app.staticTexts["userId"].label.hasPrefix("usr_"))
        XCTAssertEqual(app.staticTexts["amr"].label, "pwd")
        screenshot("signed-in")

        app.buttons["userinfo"].tap()
        let userinfo = NSPredicate(format: "label == %@", "userinfo: \(address)")
        expectation(for: userinfo, evaluatedWith: app.staticTexts["result"])
        waitForExpectations(timeout: 20)

        app.buttons["refresh"].tap()
        let refreshed = NSPredicate(format: "label BEGINSWITH 'Access token valid until'")
        expectation(for: refreshed, evaluatedWith: app.staticTexts["result"])
        waitForExpectations(timeout: 20)
        XCTAssertFalse(app.staticTexts["error"].exists)

        // The session is in the Keychain: a relaunch is still signed in.
        app.terminate()
        app = launchLive(settings, keychain: keychain)
        XCTAssertTrue(app.staticTexts["email"].waitForExistence(timeout: 20), "still signed in after a relaunch")
        XCTAssertEqual(app.staticTexts["email"].label, address)

        // Sign-out ends the 9in session in the browser. Nobody closes the sheet here, so signOut()
        // returns (the app's buttons are enabled again) only once 9in redirected to
        // io.ninein.example:/signed-out, which it does after ending the session. (That the next sign-in
        // then asks for the password is checked over HTTP by the package's live tests.)
        app.buttons["signOut"].tap()
        allowSignInPrompt()
        let done = NSPredicate(format: "exists == true AND enabled == true")
        expectation(for: done, evaluatedWith: app.buttons["signIn"])
        waitForExpectations(timeout: 45)
        XCTAssertFalse(app.staticTexts["error"].exists, "sign-out came back without an error")
        XCTAssertFalse(app.staticTexts["email"].exists)
        screenshot("signed-out")

        // Signed out for good: a relaunch shows the start screen.
        app.terminate()
        app = launchLive(settings, keychain: keychain)
        XCTAssertTrue(app.buttons["signIn"].waitForExistence(timeout: 20), "still signed out after a relaunch")
    }
}
