#!/bin/bash
# The example app against a real 9in tenant (the sdk-e2e sandbox and its "E2E Mobile" Native /
# Mobile client), through the system browser sheet in the iOS Simulator: the hosted sign-in form,
# then a full sign-in with a new sandbox user, userinfo, refresh, relaunch and sign-out. The user is
# deleted afterwards with the confidential E2E Server client. Settings come from the e2e file and
# are never printed.
#
#   NINE_E2E_ENV=/path/to/.env.e2e ./live-ui-tests.sh ['platform=iOS Simulator,name=iPhone 17']
set -euo pipefail
cd "$(dirname "$0")"
: "${NINE_E2E_ENV:?set NINE_E2E_ENV to the e2e settings file}"
setting() { grep -E "^$1=" "$NINE_E2E_ENV" | head -1 | cut -d= -f2-; }

email="ios-ui-$(date +%s)@sandbox.e2e.test"
destination=${1:-"platform=iOS Simulator,name=iPhone 17"}
status=0
TEST_RUNNER_NINE_LIVE_ISSUER=$(setting SANDBOX_ISSUER) \
TEST_RUNNER_NINE_LIVE_CLIENT_ID=$(setting NATIVE_CLIENT_ID) \
TEST_RUNNER_NINE_LIVE_REDIRECT_URI=$(setting NATIVE_REDIRECT_URI) \
TEST_RUNNER_NINE_LIVE_EMAIL=$email \
  xcodebuild test -project NineExample.xcodeproj -scheme NineExample -destination "$destination" \
    -only-testing:NineExampleUITests/NineExampleUITests/testOpensTheHostedLoginPage \
    -only-testing:NineExampleUITests/NineExampleUITests/testLiveSignInEndToEnd \
    ${NINE_RESULT_BUNDLE:+-resultBundlePath "$NINE_RESULT_BUNDLE"} || status=$?

echo "Deleting the sandbox user $email"
ISSUER=$(setting SANDBOX_ISSUER) CLIENT=$(setting SERVER_CLIENT_ID) SECRET=$(setting SERVER_CLIENT_SECRET) EMAIL=$email python3 - <<'PY'
import base64, json, os, urllib.error, urllib.parse, urllib.request
issuer, email = os.environ["ISSUER"], os.environ["EMAIL"]
basic = base64.b64encode(f'{urllib.parse.quote(os.environ["CLIENT"], safe="")}:{urllib.parse.quote(os.environ["SECRET"], safe="")}'.encode()).decode()
form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "management:users:read management:users:write"}).encode()
agent = {"User-Agent": "9in-e2e-ios/1.0"}  # Cloudflare refuses Python's default User-Agent (error 1010)
request = urllib.request.Request(f"{issuer}/oauth/token", data=form, headers={"Authorization": f"Basic {basic}", "Accept": "application/json", **agent})
token = json.load(urllib.request.urlopen(request, timeout=20))["access_token"]
auth = {"Authorization": f"Bearer {token}", "Accept": "application/json", **agent}
try:
    user = json.load(urllib.request.urlopen(urllib.request.Request(f"{issuer}/api/v1/users/lookup?email={urllib.parse.quote(email)}", headers=auth), timeout=20))["user"]
except urllib.error.HTTPError as error:
    print("no such user (the sign-in didn't create it)" if error.code == 404 else f"lookup failed: HTTP {error.code}")
else:
    urllib.request.urlopen(urllib.request.Request(f"{issuer}/api/v1/users/{urllib.parse.quote(user['id'])}", method="DELETE", headers=auth), timeout=20)
    print("deleted")
PY
exit $status
