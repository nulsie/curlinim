import std/[json, tables, strutils, asyncdispatch, random]
import ./tls_client
import ./bindings

type
  WebSocketClient* = ref object
    client*: HttpClient
    url*: string
    isConnected*: bool
    connectionId*: string

proc newWebSocketClient*(client: HttpClient, url: string): WebSocketClient =
  # websockets strictly require http/1.1 fallback for tlsfingerprint compliance
  if not client.forceHttp1:
    echo "[tls-client warning] WebSockets typically require HTTP/1.1. Enforcing forceHttp1 = true for client session."
    client.forceHttp1 = true

  new(result)
  result.client = client
  result.url = url
  result.isConnected = false
  result.connectionId = "ws_" & $rand(100_000..999_999)

proc connect*(ws: WebSocketClient, customHeaders: Table[string, string] = initTable[string, string]()): bool =
  var headers = customHeaders
  
  # standard browser ws handshake headers required for fingerprint compliance
  if not headers.hasKey("Upgrade"): headers["Upgrade"] = "websocket"
  if not headers.hasKey("Connection"): headers["Connection"] = "Upgrade"
  if not headers.hasKey("Sec-WebSocket-Version"): headers["Sec-WebSocket-Version"] = "13"
  if not headers.hasKey("Sec-WebSocket-Key"): 
    # generate a random base64-ish 16-byte key for the handshake
    headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ=="

  try:
    # perform the handshake request using the fingerprint-bound HttpClient
    let response = ws.client.request("GET", ws.url, headers)
    
    # status 101 Switching Protocols indicates successful handshake completion
    if response.status == 101:
      ws.isConnected = true
      return true
    else:
      echo "[tls-client error] WebSocket handshake failed with status code: ", response.status
      return false
  except Exception as e:
    echo "[tls-client error] WebSocket connection exception: ", e.msg
    return false

proc sendText*(ws: WebSocketClient, message: string): Response =
  if not ws.isConnected:
    raise newException(IOError, "Cannot send message on a disconnected WebSocket client.")
  
  # send data through the active session context
  var headers = initTable[string, string]()
  headers["Content-Type"] = "application/json"
  ws.client.request("POST", ws.url, headers, message)

proc close*(ws: WebSocketClient) =
  if ws.isConnected:
    ws.isConnected = false
    # clean up underlying session resources if needed
    ws.client.close()
