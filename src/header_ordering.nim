import std/[json, tables, strutils]
import ./tls_client
import ./bindings
import ./proxy_manager

type
  BrowserPreset* = enum
    bpChrome, bpFirefox, bpSafari

proc getPseudoHeaderOrder*(browser: BrowserPreset): seq[string] =
  case browser
  of bpChrome:
    result = @[":method", ":authority", ":path", ":scheme"]
  of bpFirefox:
    result = @[":method", ":path", ":authority", ":scheme"]
  of bpSafari:
    result = @[":method", ":path", ":authority", ":scheme"]

proc getDefaultHeaderOrder*(browser: BrowserPreset): seq[string] =
  case browser
  of bpChrome:
    result = @[
      "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", 
      "sec-ch-ua-platform", "user-agent", "accept", "sec-fetch-site", 
      "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language"
    ]
  of bpFirefox:
    result = @[
      "host", "user-agent", "accept", "accept-language", 
      "accept-encoding", "connection", "upgrade-insecure-requests", 
      "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"
    ]
  of bpSafari:
    result = @[
      "host", "user-agent", "accept", "accept-language", 
      "accept-encoding", "connection"
    ]

# enhanced request proc taking an OrderedTable to keep header sequence correctly
proc requestOrdered*(
    client: HttpClient, 
    httpMethod: string, 
    url: string, 
    headers: OrderedTable[string, string],
    explicitHeaderOrder: seq[string] = @[],
    body: string = ""
): Response =
  var activeProxy = client.currentProxy
  var allowHttp3 = client.enableHttp3
    
  if activeProxy.len > 0:
    let proxyCfg = parseProxyUrl(activeProxy)
    ensureProxyHttp3Safe(proxyCfg, allowHttp3)

  var headerJson = newJObject()
  var headerOrder = newJArray()

  # populate json key-values
  for k, v in headers:
    headerJson[k] = %v

  # use explicit header order if given; ifnot extract keys seqly from OrderedTable
  if explicitHeaderOrder.len > 0:
    for h in explicitHeaderOrder:
      headerOrder.add(%h)
  else:
    for k, _ in headers:
      headerOrder.add(%k)

  # copy base template for zero-alloc efficiency
  var payload = client.basePayloadJson.copy()

  payload["requestUrl"] = %url
  payload["requestMethod"] = %httpMethod.toUpperAscii()
  payload["headers"] = headerJson
  payload["headerOrder"] = headerOrder

  if client.pseudoHeaderOrder.len > 0:
    var phArray = newJArray()
    for pseudo in client.pseudoHeaderOrder:
      phArray.add(%pseudo)
    payload["pseudoHeaderOrder"] = phArray

  if body.len > 0:
    payload["requestBody"] = %body
  else:
    if payload.hasKey("requestBody"):
      payload.delete("requestBody")

  let rawResStr = executeRequest($payload)
  let jsonRes = parseJson(rawResStr)

  if jsonRes.hasKey("error") and jsonRes["error"].getBool():
    let errMessage = 
      if jsonRes.hasKey("message"): jsonRes["message"].getStr()
      else: "Unknown TLS Client header error"
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
