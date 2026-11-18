import std/[tables, json, strutils, os]
import ./tls_client
import ./fingerprint_builder

proc runTestSuites() =
  echo "=================================================="
  echo "       NIM TLS CLIENT - INTEGRATION TESTS         "
  echo "=================================================="

  # 1. Initialization & Standard GET Request Test
  echo "\n[Test 1] Initializing Chrome 133 client & executing GET..."
  var client: HttpClient
  try:
    client = newHttpClient(
      profile = cpChrome133, 
      timeoutSeconds = 15,
      followRedirects = true,
      insecureSkipVerify = false
    )
    echo "  -> Client initialized successfully with Session ID: ", client.sessionId

    let res = client.get("https://httpbin.org/get")
    echo "  -> Status Code: ", res.status
    echo "  -> Headers Count: ", res.headers.len
    
    if res.status == 200:
      echo "  [PASS] GET request succeeded with status 200."
    else:
      echo "  [FAIL] Expected status 200, got: ", res.status
  except Exception as e:
    echo "  [FAIL] GET request threw an exception: ", e.msg

  # 2. TLS Fingerprint Verification Test
  echo "\n[Test 2] Verifying TLS fingerprint against tls.peet.ws..."
  try:
    let fpData = client.verifyFingerprint("https://tls.peet.ws/api/all")
    if fpData.hasKey("ja4"):
      echo "  -> Detected JA4 Fingerprint: ", fpData["ja4"].getStr()
    if fpData.hasKey("http_version"):
      echo "  -> Protocol Negotiated: ", fpData["http_version"].getStr()
    echo "  [PASS] Fingerprint verification endpoint reached and parsed successfully."
  except Exception as e:
    echo "  [FAIL/WARN] Fingerprint check failed (endpoint might be down or blocked): ", e.msg

  # 3. POST Request & Custom Headers Test
  echo "\n[Test 3] Testing POST request with JSON payload and custom headers..."
  try:
    var headers = initTable[string, string]()
    headers["Content-Type"] = "application/json"
    headers["X-Custom-Test-Header"] = "NimTlsClient-v1"

    let payloadJson = %* {"user": "nim_tester", "active": true}
    let postRes = client.post("https://httpbin.org/post", $payloadJson, headers)
    
    echo "  -> POST Status Code: ", postRes.status
    if postRes.status == 200 and postRes.body.contains("X-Custom-Test-Header"):
      echo "  [PASS] POST request and custom headers reflected correctly."
    else:
      echo "  [FAIL] POST response did not match expected echo output."
  except Exception as e:
    echo "  [FAIL] POST request threw an exception: ", e.msg

  # 4. Error Handling & Exception Condition Test
  echo "\n[Test 4] Testing error conditions (Invalid Domain / Connection Refused)..."
  try:
    # Intentionally trigger a resolution or connection failure
    discard client.get("https://this-domain-definitely-does-not-exist-xyz987.com")
    echo "  [FAIL] Expected an exception for non-existent domain, but none was raised."
  except IOError as e:
    echo "  -> Successfully caught expected TLS/IO error: ", e.msg
    echo "  [PASS] Error propagation mechanism is working correctly."
  except Exception as e:
    echo "  -> Caught general exception: ", e.msg
    echo "  [PASS] Error propagation mechanism is working correctly."

  echo "\n=================================================="
  echo "           TEST SUITE EXECUTION COMPLETE          "
  echo "=================================================="

when isMainModule:
  runTestSuites()
