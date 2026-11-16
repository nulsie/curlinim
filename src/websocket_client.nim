import std/[json, tables, strutils, base64]
import ./tls_client
import ./bindings

type
  WsMessageType* = enum
    wsText = 1
    wsBinary = 2
    wsClose = 8
    wsPing = 9
    wsPong = 10

  WebSocketClient* = ref object
    httpClient*: HttpClient
    url*: string
    connectionId*: string
    isConnected*: bool

proc `=destroy`(ws: var WebSocketClient) =
  if ws.isConnected and ws.connectionId.len > 0:
    try:
      discard executeWsClose($(%* {"connectionId": ws.connectionId}))
    except:
      discard
    ws.isConnected = false

proc newWebSocketClient*(client: HttpClient, url: string): WebSocketClient =
  WebSocketClient(
    httpClient: client,
    url: url,
    connectionId: "",
    isConnected: false
  )

proc connect*(
    ws: WebSocketClient,
    headers: Table[string, string] = initTable[string, string](),
    headerOrder: seq[string] = @[],
    handshakeTimeoutMs: int = 15000,
    enableCompression: bool = true
): bool =
  var headerJson = newJObject()
  var orderArr = newJArray()

  for k, v in headers:
    headerJson[k] = %v
    if headerOrder.len == 0:
      orderArr.add(%k.toLowerAscii())

  if headerOrder.len > 0:
    for h in headerOrder:
      orderArr.add(%h.toLowerAscii())

  # reuses the HttpClient's TLS fingerprint, proxy, and cookies via sessionid
  var payload = %* {
    "sessionId": ws.httpClient.sessionId,
    "tlsClientIdentifier": $ws.httpClient.profile,
    "requestUrl": ws.url,
    "headers": headerJson,
    "headerOrder": orderArr,
    "handshakeTimeoutMilliseconds": handshakeTimeoutMs,
    "enableCompression": enableCompression,
    "insecureSkipVerify": ws.httpClient.insecureSkipVerify
  }

  if ws.httpClient.currentProxy.len > 0:
    payload["proxyUrl"] = %ws.httpClient.currentProxy

  let res = executeWsConnect($payload)

  if res.hasKey("error") and res["error"].getBool():
    let errMsg = if res.hasKey("message"): res["message"].getStr() else: "Unknown WebSocket connect error"
    raise newException(IOError, "TLS WebSocket Connect Error: " & errMsg)

  ws.connectionId = res["connectionId"].getStr()
  ws.isConnected = true
  return true

proc send*(ws: WebSocketClient, data: string, msgType: WsMessageType = wsText) =
  if not ws.isConnected or ws.connectionId.len == 0:
    raise newException(IOError, "Cannot send on a disconnected WebSocket.")

  let isBinary = (msgType == wsBinary)
  let payloadData = if isBinary: encode(data) else: data

  let payload = %* {
    "connectionId": ws.connectionId,
    "messageType": int(msgType),
    "data": payloadData,
    "isBase64": isBinary
  }

  let res = executeWsWrite($payload)
  if res.hasKey("error") and res["error"].getBool():
    ws.isConnected = false
    let errMsg = if res.hasKey("message"): res["message"].getStr() else: "WebSocket write failed"
    raise newException(IOError, "TLS WebSocket Write Error: " & errMsg)

proc sendText*(ws: WebSocketClient, message: string) =
  ws.send(message, wsText)

proc sendBinary*(ws: WebSocketClient, data: string) =
  ws.send(data, wsBinary)

proc receiveMessage*(ws: WebSocketClient, timeoutMs: int = 30000): tuple[msgType: WsMessageType, data: string] =
  if not ws.isConnected or ws.connectionId.len == 0:
    raise newException(IOError, "Cannot read from a disconnected WebSocket.")

  let payload = %* {
    "connectionId": ws.connectionId,
    "timeoutMs": timeoutMs
  }

  let res = executeWsRead($payload)
  if res.hasKey("error") and res["error"].getBool():
    ws.isConnected = false
    let errMsg = if res.hasKey("message"): res["message"].getStr() else: "WebSocket read failed or closed"
    raise newException(IOError, "TLS WebSocket Read Error: " & errMsg)

  let mTypeInt = res["messageType"].getInt(1)
  let mType = case mTypeInt
    of 2: wsBinary
    of 8: wsClose
    of 9: wsPing
    of 10: wsPong
    else: wsText

  var body = res["data"].getStr()
  if res.hasKey("isBase64") and res["isBase64"].getBool():
    body = decode(body)

  if mType == wsClose:
    ws.isConnected = false

  return (msgType: mType, data: body)

proc close*(ws: WebSocketClient) =
  if ws.isConnected and ws.connectionId.len > 0:
    try:
      discard executeWsClose($(%* {"connectionId": ws.connectionId}))
    finally:
      ws.isConnected = false
      ws.connectionId = ""
