import std/[json, tables, options, strutils, times, random, asyncdispatch, threadpool, os]
import ./bindings
import ./proxy_manager

type
  ClientProfile* = enum
    cpChrome133 = "chrome_133"
    cpFirefox132 = "firefox_132"
    cpSafari18  = "safari_ios_18_0"

  Response* = object
    status*: int
    body*: string
    headers*: Table[string, seq[string]]
    cookies*: Table[string, string]
    rawJson*: JsonNode

  HttpClientObj = object
    profile*: ClientProfile
    timeoutSeconds*: int
    followRedirects*: bool
    insecureSkipVerify*: bool  # field for certificate verification control
    sessionId*: string   # tracks the persistent session id
    proxyRotator*: ProxyRotator   # added for adding the rotator support
    currentProxy*: string 
    proxy*: string        # proxy url config field
    forceHttp1*: bool                 # force http/1.1 fallback instead of http/2
    enableHttp3*: bool # the http/3 enabler flag
    pseudoHeaderOrder*: seq[string]   # custom http/2 pseudo-header ordering
    # removed the lock field as it caused compilation err bec nim 2.x do the destructor handlers for objs with lock
    basePayloadJson*: JsonNode # to cache json template

  HttpClient* = ref HttpClientObj

proc `=destroy`(clientObj: var HttpClientObj) =
  # automatically invoked by nim 2.x when HttpClientObj goes out of scope 
  # or its ref count drops to zero this prevents go-side session leaks
  if clientObj.sessionId.len > 0:
    executeDestroySession(clientObj.sessionId)
    clientObj.sessionId = ""

  # structure representing a form field or file upload part
  MultipartField* = object
    name*: string
    value*: string
    filename*: string     # leave empty if it's a standard text form field
    contentType*: string 

proc newHttpClient*(
    profile: ClientProfile = cpChrome133, 
    timeoutSeconds: int = 30, 
    followRedirects: bool = true,
    insecureSkipVerify: bool = false, 
    sessionId: string = "",
    proxy: string = "",
    proxyPool: seq[string] = @[],
    rotationStrategy: RotationStrategy = rsRoundRobin,
    forceHttp1: bool = false,
    enableHttp3: bool = false,
    pseudoHeaderOrder: seq[string] = @[],
    libPath: string = defaultLibPath
): HttpClient =
  loadTlsClient(libPath)
  
  var activeSessionId = sessionId
  if activeSessionId.len == 0:
    randomize()
    activeSessionId = "session_" & $rand(100_000..999_999)

  # init rotator from single proxy or proxy pool
  var pool = proxyPool
  if pool.len == 0 and proxy.len > 0:
    pool = @[proxy]
    
  let rotator = newProxyRotator(pool, rotationStrategy)
  let initialProxy = if rotator.proxies.len > 0: rotator.nextProxy() else: ""

  # --- Pre-build the static payload template ---
  var baseJson = %* {
    "tlsClientIdentifier": $profile,
    "followRedirects": followRedirects,
    "insecureSkipVerify": insecureSkipVerify,
    "withoutCookieJar": false,
    "timeoutSeconds": timeoutSeconds,
    "sessionId": activeSessionId,
    "forceHttp1": forceHttp1,
    "isByteRequest": false,
    "isByteResponse": false
  }
  
  if initialProxy.len > 0:
    baseJson["proxyUrl"] = %initialProxy
  
  if pseudoHeaderOrder.len > 0:
    var phArray = newJArray()
    for pseudo in pseudoHeaderOrder:
      phArray.add(%pseudo)
    baseJson["pseudoHeaderOrder"] = phArray

  new(result)
  result.profile = profile
  result.timeoutSeconds = timeoutSeconds
  result.followRedirects = followRedirects
  result.insecureSkipVerify = insecureSkipVerify
  result.sessionId = activeSessionId
  result.proxyRotator = rotator
  result.currentProxy = initialProxy
  result.forceHttp1 = forceHttp1
  result.enableHttp3 = enableHttp3
  result.pseudoHeaderOrder = pseudoHeaderOrder
  result.basePayloadJson = baseJson

proc rotateProxy*(client: HttpClient) =
  if client == nil: return
  if client.proxyRotator != nil and client.proxyRotator.proxies.len > 0:
    client.currentProxy = client.proxyRotator.nextProxy()

proc clone*(client: HttpClient, newSessionId: string = ""): HttpClient =
  # creates an isolated worker clone with a new unique sessionid for the worker-clone pattern which is afix for the risks of
  # removing the lock guards
  var sid = newSessionId
  if sid.len == 0:
    randomize()
    sid = "session_" & $rand(100_000..999_999)

  # extract existing proxy pool urls from rotator if present
  var pool: seq[string] = @[]
  if client.proxyRotator != nil:
    for p in client.proxyRotator.proxies:
      pool.add(p.rawUrl)

  newHttpClient(
    profile = client.profile,
    timeoutSeconds = client.timeoutSeconds,
    followRedirects = client.followRedirects,
    insecureSkipVerify = client.insecureSkipVerify,
    sessionId = sid,
    proxyPool = pool,
    rotationStrategy = if client.proxyRotator != nil: client.proxyRotator.strategy else: rsRoundRobin,
    forceHttp1 = client.forceHttp1,
    enableHttp3 = client.enableHttp3,
    pseudoHeaderOrder = client.pseudoHeaderOrder
  )

proc request*(
    client: HttpClient, 
    httpMethod: string, 
    url: string, 
    headers: Table[string, string] = initTable[string, string](),
    body: string = ""
): Response =
  var activeProxy = client.currentProxy
  var allowHttp3 = client.enableHttp3
    
  if activeProxy.len > 0:
    let proxyCfg = parseProxyUrl(activeProxy)
    ensureProxyHttp3Safe(proxyCfg, allowHttp3)

  var headerJson = newJObject()
  var headerOrder = newJArray()

  for k, v in headers:
    headerJson[k] = %v
    headerOrder.add(%k)

  # zero-alloc optim copy base template instead of rebuilding
  var payload = client.basePayloadJson.copy()

  # inject dynamic req-specific fields
  payload["requestUrl"] = %url
  payload["requestMethod"] = %httpMethod.toUpperAscii()
  payload["headers"] = headerJson
  payload["headerOrder"] = headerOrder

  if body.len > 0:
    payload["requestBody"] = %body
  else:
    # safely clear requestBody if it was populated in a previous request loop
    if payload.hasKey("requestBody"):
      payload.delete("requestBody")

  let rawResStr = executeRequest($payload)
  let jsonRes = parseJson(rawResStr)

  if jsonRes.hasKey("error") and jsonRes["error"].getBool():
    let errMessage = 
      if jsonRes.hasKey("message"): jsonRes["message"].getStr()
      elif jsonRes.hasKey("status"): 
        if jsonRes["status"].kind == JString: jsonRes["status"].getStr()
        elif jsonRes["status"].kind == JInt: $jsonRes["status"].getInt()
        else: "Unknown status type"
      else: "Unknown TLS Client error"
    raise newException(IOError, "TLS Client Error: " & errMessage)

  var respHeaders = initTable[string, seq[string]]()
  if jsonRes.hasKey("headers") and jsonRes["headers"].kind == JObject:
    for k, v in jsonRes["headers"]:
      var vals: seq[string] = @[]
      if v.kind == JArray:
        for item in v: vals.add(item.getStr())
      respHeaders[k] = vals

  var respCookies = initTable[string, string]()
  if jsonRes.hasKey("cookies") and jsonRes["cookies"].kind == JObject:
    for k, v in jsonRes["cookies"]:
      if v.kind == JObject and v.hasKey("value"):
        respCookies[k] = v["value"].getStr()
      elif v.kind == JString:
        respCookies[k] = v.getStr()

  Response(
    status: jsonRes["status"].getInt(),
    body: jsonRes["body"].getStr(),
    headers: respHeaders,
    cookies: respCookies,
    rawJson: jsonRes
  )

proc get*(client: HttpClient, url: string, headers: Table[string, string] = initTable[string, string]()): Response =
  client.request("GET", url, headers)

proc post*(client: HttpClient, url: string, body: string, headers: Table[string, string] = initTable[string, string]()): Response =
  client.request("POST", url, headers, body)

proc put*(
    client: HttpClient, 
    url: string, 
    body: string = "", 
    headers: Table[string, string] = initTable[string, string]()
): Response =
  client.request("PUT", url, headers, body)

proc delete*(
    client: HttpClient, 
    url: string, 
    headers: Table[string, string] = initTable[string, string]()
): Response =
  client.request("DELETE", url, headers)

proc patch*(
    client: HttpClient, 
    url: string, 
    body: string = "", 
    headers: Table[string, string] = initTable[string, string]()
): Response =
  client.request("PATCH", url, headers, body)

proc head*(
    client: HttpClient, 
    url: string, 
    headers: Table[string, string] = initTable[string, string]()
): Response =
  client.request("HEAD", url, headers)

# --- multipart form data builder & handlers

proc buildMultipartBody*(fields: seq[MultipartField], boundary: string): string =
  var res = ""
  for field in fields:
    res.add("--" & boundary & "\r\n")
    if field.filename.len > 0:
      let cType = if field.contentType.len > 0: field.contentType else: "application/octet-stream"
      res.add("Content-Disposition: form-data; name=\"" & field.name & "\"; filename=\"" & field.filename & "\"\r\n")
      res.add("Content-Type: " & cType & "\r\n")
    else:
      res.add("Content-Disposition: form-data; name=\"" & field.name & "\"\r\n")
    res.add("\r\n")
    res.add(field.value & "\r\n")
  res.add("--" & boundary & "--\r\n")
  result = res

proc postMultipart*(
    client: HttpClient, 
    url: string, 
    fields: seq[MultipartField], 
    headers: Table[string, string] = initTable[string, string]()
): Response =
  let boundary = "----NimTlsClientBoundary" & $rand(100_000_000..999_999_999)
  let bodyStr = buildMultipartBody(fields, boundary)

  # case-insensitive check to see if content-type was manually supplied
  var reqHeaders = headers
  var hasContentType = false
  for k, _ in reqHeaders:
    if k.toLowerAscii() == "content-type":
      hasContentType = true
      break

  if not hasContentType:
    reqHeaders["Content-Type"] = "multipart/form-data; boundary=" & boundary

  client.request("POST", url, reqHeaders, bodyStr)

# --- response streaming & chunked iteration ---

iterator iterContent*(response: Response, chunkSize: int = 8192): string =
  var pos = 0
  let bodyLen = response.body.len
  if bodyLen == 0:
    yield ""
  else:
    while pos < bodyLen:
      let endPos = min(pos + chunkSize, bodyLen)
      yield response.body[pos..<endPos]
      pos = endPos

proc streamRequest*(
    client: HttpClient,
    httpMethod: string,
    url: string,
    onChunk: proc(chunk: string) {.closure.},
    chunkSize: int = 8192,
    headers: Table[string, string] = initTable[string, string](),
    body: string = ""
): Response =
  let response = client.request(httpMethod, url, headers, body)
  for chunk in response.iterContent(chunkSize):
    onChunk(chunk)
  return response

# --- async wrappers ---

proc requestAsync*(
    client: HttpClient, 
    httpMethod: string, 
    url: string, 
    headers: Table[string, string] = initTable[string, string](),
    body: string = ""
): Future[Response] {.async.} =
  # pass isolated parameters instead of spawning the raw client ref containing lock
  let cClient = client
  let cMethod = httpMethod
  let cUrl = url
  let cHeaders = headers
  let cBody = body

  let flowVar = spawn cClient.request(cMethod, cUrl, cHeaders, cBody)
  while not isReady(flowVar):
    await sleepAsync(5)
  return ^flowVar

proc getAsync*(client: HttpClient, url: string, headers: Table[string, string] = initTable[string, string]()): Future[Response] {.async.} =
  return await client.requestAsync("GET", url, headers)

proc postAsync*(client: HttpClient, url: string, body: string, headers: Table[string, string] = initTable[string, string]()): Future[Response] {.async.} =
  return await client.requestAsync("POST", url, headers, body = body)

proc postMultipartAsync*(
    client: HttpClient, 
    url: string, 
    fields: seq[MultipartField], 
    headers: Table[string, string] = initTable[string, string]()
): Future[Response] {.async.} =
  let cClient = client
  let cUrl = url
  let cFields = fields
  let cHeaders = headers

  let flowVar = spawn cClient.postMultipart(cUrl, cFields, cHeaders)
  while not isReady(flowVar):
    await sleepAsync(5)
  return ^flowVar

proc putAsync*(
    client: HttpClient, 
    url: string, 
    body: string = "", 
    headers: Table[string, string] = initTable[string, string]()
): Future[Response] {.async.} =
  return await client.requestAsync("PUT", url, headers, body = body)

proc deleteAsync*(
    client: HttpClient, 
    url: string, 
    headers: Table[string, string] = initTable[string, string]()
): Future[Response] {.async.} =
  return await client.requestAsync("DELETE", url, headers)

proc patchAsync*(
    client: HttpClient, 
    url: string, 
    body: string = "", 
    headers: Table[string, string] = initTable[string, string]()
): Future[Response] {.async.} =
  return await client.requestAsync("PATCH", url, headers, body = body)

proc headAsync*(
    client: HttpClient, 
    url: string, 
    headers: Table[string, string] = initTable[string, string]()
): Future[Response] {.async.} =
  return await client.requestAsync("HEAD", url, headers)

# --- destructor hooks ---

proc close*(client: HttpClient) =
  if client == nil: return
  if client.sessionId.len > 0:
    executeDestroySession(client.sessionId)
    client.sessionId = ""

# --- cookie jar export/import utils ---

proc exportCookieHeader*(cookies: Table[string, string]): string =
  var parts: seq[string] = @[]
  for k, v in cookies:
    parts.add(k & "=" & v)
  result = parts.join("; ")

proc exportCookiesToJson*(response: Response): string =
  var jObj = newJObject()
  for k, v in response.cookies:
    jObj[k] = %v
  result = $jObj

proc importCookiesFromJson*(jsonStr: string): Table[string, string] =
  var res = initTable[string, string]()
  let node = parseJson(jsonStr)
  if node.kind == JObject:
    for k, v in node:
      if v.kind == JString:
        res[k] = v.getStr()
  result = res
