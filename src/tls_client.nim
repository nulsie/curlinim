import std/[json, tables, options, strutils, times, random, asyncdispatch, threadpool, os]
import ./bindings

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

  HttpClient* = object
    profile*: ClientProfile
    timeoutSeconds*: int
    followRedirects*: bool
    sessionId*: string   # tracks the persistent session id
    proxy*: string        # proxy url config field
    forceHttp1*: bool                 # force http/1.1 fallback instead of http/2
    pseudoHeaderOrder*: seq[string]   # custom http/2 pseudo-header ordering

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
    sessionId: string = "",
    proxy: string = "",
    forceHttp1: bool = false,
    pseudoHeaderOrder: seq[string] = @[],
    libPath: string = defaultLibPath
): HttpClient =
  loadTlsClient(libPath)
  
  # auto-generate a unique session id if one isn't provided
  var activeSessionId = sessionId
  if activeSessionId.len == 0:
    randomize()
    activeSessionId = "session_" & $rand(100_000..999_999)

  HttpClient(
    profile: profile, 
    timeoutSeconds: timeoutSeconds, 
    followRedirects: followRedirects,
    sessionId: activeSessionId,
    proxy: proxy,
    forceHttp1: forceHttp1,
    pseudoHeaderOrder: pseudoHeaderOrder
  )

proc request*(
    client: HttpClient, 
    httpMethod: string, 
    url: string, 
    headers: Table[string, string] = initTable[string, string](),
    body: string = ""
): Response =
  var headerJson = newJObject()
  var headerOrder = newJArray()

  for k, v in headers:
    headerJson[k] = %v
    headerOrder.add(%k)

  # build the base payload including the persistent sessionId
  var payload = %* {
    "tlsClientIdentifier": $client.profile,
    "followRedirects": client.followRedirects,
    "insecureSkipVerify": false,
    "withoutCookieJar": false,
    "timeoutSeconds": client.timeoutSeconds,
    "sessionId": client.sessionId,
    "requestUrl": url,
    "requestMethod": httpMethod.toUpperAscii(),
    "headers": headerJson,
    "headerOrder": headerOrder,
    "isByteRequest": false,
    "isByteResponse": false,
    "forceHttp1": client.forceHttp1
  }

  # inject proxyUrl into the payload if defined
  if client.proxy.len > 0:
    payload["proxyUrl"] = %client.proxy

  if client.pseudoHeaderOrder.len > 0:
    var phArray = newJArray()
    for pseudo in client.pseudoHeaderOrder:
      phArray.add(%pseudo)
    payload["pseudoHeaderOrder"] = phArray

  if body.len > 0:
    payload["requestBody"] = %body

  let rawResStr = executeRequest($payload)
  let jsonRes = parseJson(rawResStr)

  # error check handling both string/int formats safely
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
  let flowVar = spawn client.request(httpMethod, url, headers, body)
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
  let flowVar = spawn client.postMultipart(url, fields, headers)
  while not isReady(flowVar):
    await sleepAsync(5)
  return ^flowVar

# --- destructor hooks ---

proc close*(client: var HttpClient) =
  if client.sessionId.len > 0:
    executeDestroySession(client.sessionId)
    client.sessionId = "" # Prevent double destruction

proc `=destroy*(client: var HttpClient) =
  if client.sessionId.len > 0:
    try:
      executeDestroySession(client.sessionId)
    except:
      discard # Destructors must suppress exceptions to avoid crashing runtime unwinding
