# completely re-written websocket client functionality, upgraded from past stub
import std/[net, strutils, random, uri, base64, endians, times, tables]
import ./tls_client

type
  Opcode* = enum
    opContinuation = 0x0
    opText         = 0x1
    opBinary       = 0x2
    opClose        = 0x8
    opPing         = 0x9
    opPong         = 0xA

  WebSocketClient* = ref object
    socket*: Socket
    sslContext*: SslContext
    url*: Uri
    isConnected*: bool
    isSecure*: bool

proc newWebSocketClient*(url: string, insecureSkipVerify: bool = false): WebSocketClient =
  new(result)
  result.url = parseUri(url)
  result.isConnected = false
  result.isSecure = result.url.scheme.toLowerAscii() == "wss"
  
  if result.isSecure:
    result.sslContext = newContext(verifyMode = if insecureSkipVerify: CVerifyNone else: CVerifyPeer)
  else:
    result.sslContext = nil

proc connect*(ws: WebSocketClient, customHeaders: Table[string, string] = initTable[string, string]()): bool =
  let host = ws.url.hostname
  var port = ws.url.port
  if port.len == 0:
    port = if ws.isSecure: "443" else: "80"

  var sock = socket(socketProtocol = SP_TCP)
  try:
    sock.connect(host, Port(parseInt(port)))
  except Exception as e:
    echo "[WebSocket Error] TCP connection failed: ", e.msg
    return false

  if ws.isSecure:
    try:
      ws.sslContext.wrapSocket(sock, host)
    except Exception as e:
      echo "[WebSocket Error] SSL TLS handshake failed: ", e.msg
      sock.close()
      return false

  ws.socket = sock

  # build target uri path and query
  var path = ws.url.path
  if path.len == 0: path = "/"
  if ws.url.query.len > 0: path.add("?" & ws.url.query)

  randomize()
  # generate random 16-byte nonce for Sec-WebSocket-Key
  var nonceBytes: array[16, char]
  for i in 0..<16:
    nonceBytes[i] = char(rand(255))
  let wsKey = encode(cast[string](nonceBytes))

  # construct browser-compliant ws upgrade handshake
  var req = "GET " & path & " HTTP/1.1\r\n" &
            "Host: " & host & ":" & port & "\r\n" &
            "Upgrade: websocket\r\n" &
            "Connection: Upgrade\r\n" &
            "Sec-WebSocket-Key: " & wsKey & "\r\n" &
            "Sec-WebSocket-Version: 13\r\n" &
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\n"

  for k, v in customHeaders:
    req.add(k & ": " & v & "\r\n")
  req.add("\r\n")

  try:
    sock.send(req)

    # read http handshake response line
    let responseLine = sock.recvLine()
    if not responseLine.contains("101"):
      echo "[WebSocket Error] Handshake rejected by server, response: ", responseLine
      sock.close()
      return false

    # consume remaining http headers until empty boundary line
    while true:
      let line = sock.recvLine()
      if line == "\r" or line == "" or line.len == 0:
        break
  except Exception as e:
    echo "[WebSocket Error] Handshake communication exception: ", e.msg
    sock.close()
    return false

  ws.isConnected = true
  return true

proc sendFrame(ws: WebSocketClient, opcode: Opcode, data: string) =
  if not ws.isConnected:
    raise newException(IOError, "Cannot send message on a disconnected WebSocket client.")

  var frame: string = ""
  # FIN bit set (0x80) + opcode
  let firstByte = char(0x80 or int(opcode))
  frame.add(firstByte)

  let payloadLen = data.len
  # MASK bit must be set (0x80) for client-to-server frames per rfc 6455
  var secondByteMask: char = char(0x80)

  if payloadLen <= 125:
    frame.add(char(int(secondByteMask) or payloadLen))
  elif payloadLen <= 65535:
    frame.add(char(int(secondByteMask) or 126))
    var lenBytes: array[2, uint16]
    lenBytes[0] = uint16(payloadLen)
    var netLenBytes: array[2, byte]
    bigEndian16(addr netLenBytes[0], addr lenBytes[0])
    frame.add(cast[string](netLenBytes))
  else:
    frame.add(char(int(secondByteMask) or 127))
    var lenBytes: array[1, uint64]
    lenBytes[0] = uint64(payloadLen)
    var netLenBytes: array[8, byte]
    bigEndian64(addr netLenBytes[0], addr lenBytes[0])
    frame.add(cast[string](netLenBytes))

  # generate 4-byte random masking key
  var maskKey: array[4, byte]
  for i in 0..<4:
    maskKey[i] = byte(rand(255))
  frame.add(cast[string](maskKey))

  # mask the payload data using the random key
  var maskedData = data
  for i in 0..<payloadLen:
    maskedData[i] = char(byte(data[i]) xor maskKey[i mod 4])
  
  frame.add(maskedData)
  ws.socket.send(frame)

proc sendText*(ws: WebSocketClient, message: string) =
  ws.sendFrame(opText, message)

proc sendBinary*(ws: WebSocketClient, data: string) =
  ws.sendFrame(opBinary, data)

proc receiveMessage*(ws: WebSocketClient): tuple[opcode: Opcode, data: string] =
  if not ws.isConnected:
    raise newException(IOError, "Cannot receive message on a disconnected WebSocket client.")

  let headerBytes = ws.socket.recv(2)
  if headerBytes.len < 2:
    ws.isConnected = false
    raise newException(IOError, "WebSocket connection closed by peer.")

  let b1 = byte(headerBytes[0])
  let b2 = byte(headerBytes[1])

  let opcode = Opcode(b1 and 0x0F)
  let masked = (b2 and 0x80) != 0
  var payloadLen = uint64(b2 and 0x7F)

  if payloadLen == 126:
    let extBytes = ws.socket.recv(2)
    var netLen: uint16
    copyMem(addr netLen, unsafeAddr extBytes[0], 2)
    var hostLen: uint16
    bigEndian16(addr hostLen, addr netLen)
    payloadLen = uint64(hostLen)
  elif payloadLen == 127:
    let extBytes = ws.socket.recv(8)
    var netLen: uint64
    copyMem(addr netLen, unsafeAddr extBytes[0], 8)
    var hostLen: uint64
    bigEndian64(addr hostLen, addr netLen)
    payloadLen = hostLen

  var maskKey: array[4, byte]
  if masked:
    let maskBytes = ws.socket.recv(4)
    copyMem(addr maskKey[0], unsafeAddr maskBytes[0], 4)

  var payload = ws.socket.recv(int(payloadLen))

  if masked:
    for i in 0..<payload.len:
      payload[i] = char(byte(payload[i]) xor maskKey[i mod 4])

  if opcode == opClose:
    ws.isConnected = false
    try:
      ws.socket.close()
    except:
      discard

  return (opcode: opcode, data: payload)

proc close*(ws: WebSocketClient) =
  if ws.isConnected:
    try:
      ws.sendFrame(opClose, "")
    except:
      discard
    ws.isConnected = false
    try:
      ws.socket.close()
    except:
      discard
