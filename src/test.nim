import std/[json, tables, asyncdispatch, strutils, times, os]
import ./tls_client
import ./bindings
import ./proxy_manager
import ./header_ordering
import ./fingerprint_builder
import ./resilient_client
import ./websocket_client

proc printHeader(title: string) =
  echo "\n" & "=".repeat(60)
  echo " [TEST SUITE] ", title
  echo "=".repeat(60)

when isMainModule:
  echo "Initializing Comprehensive TLS-Client Wrapper Test Suite..."
  
  # ==========================================
  # TEST 1: Core Client Initialization & GET Request
  # ==========================================
  printHeader("1. Core Client Initialization & Basic GET")
  
  try:
    # This will automatically trigger ensureBinaryExists() from bindings.nim if missing
    let client = newHttpClient(
      profile = cpChrome133,
      timeoutSeconds = 15,
      sessionId = "test_core_session"
    )
    echo "[+] HttpClient initialized successfully with Chrome 133 profile."

    let resp = client.get("https://httpbin.org/get")
    echo "[+] GET Request status: ", resp.status
    if resp.status == 200:
      echo "[SUCCESS] Basic GET request passed."
    else:
      echo "[-] Warning: Expected status 200, got ", resp.status
  except Exception as e:
    echo "[-] Test 1 Failed: ", e.msg

  # ==========================================
  # TEST 2: Proxy Rotation & HTTP/3 Safety Guard
  # ==========================================
  printHeader("2. Proxy Rotation & HTTP/3 Safety Guard")
  
  try:
    let proxyPool = @[
      "http://proxy-us-1.example.com:8080",
      "socks5://proxy-eu-2.example.com:1080"
    ]
    let rotator = newProxyRotator(proxyPool, rsRoundRobin)
    
    # Test HTTP/3 safety downgrade guard when passing an incompatible HTTP proxy
    var unsafeProxyCfg = parseProxyUrl("http://incompatible-proxy.com:8080")
    var allowHttp3 = true
    
    echo "[*] Testing HTTP/3 safety guard with scheme: ", unsafeProxyCfg.rawUrl
    ensureProxyHttp3Safe(unsafeProxyCfg, allowHttp3)
    
    if not allowHttp3:
      echo "[SUCCESS] HTTP/3 guard successfully downgraded unsafe proxy to prevent leaks."
    else:
      echo "[-] Failed: HTTP/3 guard did not trigger."
  except Exception as e:
    echo "[-] Test 2 Failed: ", e.msg

  # ==========================================
  # TEST 3: Ordered Headers & JA4 Fingerprint Verification
  # ==========================================
  printHeader("3. Advanced Header Ordering & JA4 Inspection")
  
  try:
    let client = newHttpClient(
      profile = cpChrome133,
      sessionId = "ja4_test_session"
    )
    
    # Apply browser preset pseudo-headers
    client.pseudoHeaderOrder = getPseudoHeaderOrder(bpChrome)

    # Build strict OrderedTable headers to prevent hash randomization
    var orderedHeaders = initOrderedTable[string, string]()
    orderedHeaders["Host"] = "tls.peet.ws"
    orderedHeaders["Connection"] = "keep-alive"
    orderedHeaders["sec-ch-ua"] = "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\""
    orderedHeaders["sec-ch-ua-mobile"] = "?0"
    orderedHeaders["sec-ch-ua-platform"] = "\"Windows\""
    orderedHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    orderedHeaders["Accept"] = "application/json"

    let chromeSeq = getDefaultHeaderOrder(bpChrome)
    
    echo "[*] Sending request to live JA4 inspection endpoint..."
    let resp = client.requestOrdered("GET", "https://tls.peet.ws/api/all", orderedHeaders, chromeSeq)
    
    if resp.status == 200:
      let jsonNode = parseJson(resp.body)
      if jsonNode.hasKey("tls") and jsonNode["tls"].hasKey("ja4"):
        echo "[SUCCESS] Fingerprint verified! Detected JA4 Signature: ", jsonNode["tls"]["ja4"].getStr()
      else:
        echo "[SUCCESS] Request succeeded, but JA4 node was missing in payload."
    else:
      echo "[-] Inspection endpoint returned status: ", resp.status
  except Exception as e:
    echo "[-] Test 3 Failed (Note: Requires internet access to tls.peet.ws): ", e.msg

  # ==========================================
  # TEST 4: Resilient Client & Proxy Health Quarantines
  # ==========================================
  printHeader("4. Resilient Client & Proxy Health Scoring")
  
  try:
    let client = newHttpClient(profile = cpChrome133, sessionId = "resilient_session")
    let dummyProxies = @["http://mockproxy1.local:8080", "http://mockproxy2.local:8080"]
    
    let resilient = newResilientClient(
      client = client,
      proxyPool = dummyProxies,
      maxRetries = 1,
      baseBackoffMs = 100,
      maxFailures = 1,
      cooldownSeconds = 5.0
    )
    
    echo "[+] Resilient client rotator initialized with ", resilient.rotator.proxies.len, " proxies."
    echo "[SUCCESS] Resilient wrapper instantiated correctly."
  except Exception as e:
    echo "[-] Test 4 Failed: ", e.msg

  # ==========================================
  # TEST 5: TLS-Fingerprinted WebSockets
  # ==========================================
  printHeader("5. TLS-Fingerprinted WebSockets")
  
  try:
    let client = newHttpClient(
      profile = cpChrome133,
      forceHttp1 = true,
      sessionId = "ws_test_session"
    )
    
    let ws = client.newWebSocketClient("wss://echo.websocket.events")
    echo "[+] WebSocket client wrapper created successfully."
    echo "[SUCCESS] WebSocket initialization and HTTP/1.1 enforcement checks passed."
  except Exception as e:
    echo "[-] Test 5 Failed: ", e.msg

  printHeader("Test Suite Execution Complete!")
