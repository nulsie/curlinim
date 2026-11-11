import std/[unittest, tables, json, asyncdispatch, strutils]
import ./tls_client
import ./resilient_client
import ./proxy_manager
import ./fingerprint_builder

suite "Nim TLS Client Production & Integration Tests":

  test "1. Client Initialization & Automated Binary Bootstrap":
    # Verifies that newHttpClient successfully bootstraps/loads the FFI binary 
    # and initializes persistent session identifiers.
    let client = newHttpClient(profile = cpChrome133, timeoutSeconds = 15)
    check client != nil
    check client.sessionId.len > 0
    echo "  [+] Client successfully initialized with Session ID: ", client.sessionId

  test "2. Live GET Request (JA4 / TLS Peet Validation)":
    # Executes a live request to a public TLS fingerprint echo endpoint[cite: 1, 7].
    let client = newHttpClient(profile = cpChrome133)
    let response = client.get("https://tls.peet.ws/api/all")
    
    check response.status == 200
    check response.body.len > 0
    check response.rawJson.kind == JObject
    check response.rawJson.hasKey("http_version")
    
    echo "  [+] GET request successful. Detected HTTP Version: ", response.rawJson["http_version"].getStr()

  test "3. POST Request with Custom Headers & JSON Payload":
    # Tests request formatting, headers injection, and body submission[cite: 1].
    let client = newHttpClient(profile = cpFirefox132)
    var headers = initTable[string, string]()
    headers["Content-Type"] = "application/json"
    headers["X-Test-Header"] = "NimCffiWrapper"

    let postBody = """{"status": "testing", "version": 1.0}"""
    let response = client.post("https://httpbin.org/post", postBody, headers)
    
    check response.status == 200
    check "NimCffiWrapper" in response.body  # <--- Changed to native 'in' operator
    check "testing" in response.body
    echo "  [+] POST request payload and headers verified."

  test "4. Proxy Rotator & HTTP/3 Proxy Safety Guard":
    # Tests parsing proxy schemas and ensuring TCP-only proxies safely downgrade HTTP/3.
    let proxyPool = @["http://127.0.0.1:8080", "socks5://127.0.0.1:1080"]
    let rotator = newProxyRotator(proxyPool, rsRoundRobin)
    
    check rotator.proxies.len == 2
    check rotator.nextProxy() == "http://127.0.0.1:8080"
    check rotator.nextProxy() == "socks5://127.0.0.1:1080"

    # Test HTTP/3 proxy safety guard
    var allowH3 = true
    let httpProxyCfg = parseProxyUrl("http://insecure-tcp-proxy.com:3128")
    ensureProxyHttp3Safe(httpProxyCfg, allowH3)
    
    check allowH3 == false # Should force downgrade to prevent IP leaks over UDP/QUIC[cite: 5]
    echo "  [+] Proxy rotator and HTTP/3 safety guard logic verified."

  test "5. Custom Fingerprint Builder Configuration":
    # Tests mutating pseudo-header ordering and custom fingerprint parameters[cite: 6, 7].
    let client = newHttpClient(profile = cpChrome133)
    let customCfg = newCustomFingerprint(
      profileName = "custom_browser_v1",
      pseudoHeaderOrder = @[":method", ":path", ":authority", ":scheme"]
    )
    
    client.applyCustomFingerprint(customCfg)
    check client.pseudoHeaderOrder == @[":method", ":path", ":authority", ":scheme"]
    echo "  [+] Custom fingerprint configurations applied successfully."
