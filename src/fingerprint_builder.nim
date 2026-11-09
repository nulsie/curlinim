import std/[json, tables, strutils]
import ./tls_client

type
  CustomFingerprintConfig* = object
    profileName*: string
    pseudoHeaderOrder*: seq[string]
    defaultHeaders*: Table[string, string]
    headerOrder*: seq[string]

proc newCustomFingerprint*(
    profileName: string = "custom_browser_profile",
    pseudoHeaderOrder: seq[string] = @[":method", ":authority", ":path", ":scheme"],
    headerOrder: seq[string] = @["host", "connection", "sec-ch-ua", "user-agent", "accept", "accept-encoding", "accept-language"]
): CustomFingerprintConfig =
  CustomFingerprintConfig(
    profileName: profileName,
    pseudoHeaderOrder: pseudoHeaderOrder,
    defaultHeaders: initTable[string, string](),
    headerOrder: headerOrder
  )

proc applyCustomFingerprint*(client: HttpClient, config: CustomFingerprintConfig) =
  # 1. update client pseudo-header order configuration
  client.pseudoHeaderOrder = config.pseudoHeaderOrder
  
  # 2. mutate the cached base payload json template to reflect custom http/2 parameters
  if client.basePayloadJson != nil:
    var phArray = newJArray()
    for pseudo in config.pseudoHeaderOrder:
      phArray.add(%pseudo)
    client.basePayloadJson["pseudoHeaderOrder"] = phArray

proc verifyFingerprint*(client: HttpClient, verifyUrl: string = "https://tls.peet.ws/api/all"): JsonNode =
  # queries a public tls/ja4 validation endpoint to verify fingerprint output
  let resp = client.get(verifyUrl)
  if resp.status == 200:
    return resp.rawJson
  else:
    raise newException(IOError, "Failed to verify fingerprint. Endpoint returned status: " & $resp.status)
