import std/[dynlib, os, httpclient, strutils, json]

type
  TlsRequestProc = proc(rawPayload: cstring): cstring {.cdecl, gcsafe.}
  DestroySessionProc = proc(rawPayload: cstring): cstring {.cdecl, gcsafe.} # for the destructor hooks
  FreeMemoryProc = proc(rawPayload: cstring) {.cdecl, gcsafe.}

var
  lib: LibHandle
  reqProc: TlsRequestProc
  destroyProc: DestroySessionProc
  freeProc: FreeMemoryProc

# define other platform's default library paths too
# target release version tied to this wrapper version
const 
  TlsClientVersion* = "v1.18.1"
  defaultLibPath* = 
    when defined(windows): "binaries/libtls-client.dll"
    elif defined(macosx): "binaries/libtls-client.dylib"
    else: "binaries/libtls-client.so"

# added a dynamic lib downloader for simplicity's sake so i and you don't want to manually source tls-client sl
# this maps the current os and cpu arch to the tls-client release binary
proc getDownloadUrl*(): string =
  when defined(windows):
    when defined(amd64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & TlsClientVersion & "/libtls-client-windows-amd64-" & TlsClientVersion & ".dll"
    else:
      result = ""
  elif defined(macosx):
    when defined(arm64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & TlsClientVersion & "/libtls-client-darwin-arm64-" & TlsClientVersion & ".dylib"
    else:
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & TlsClientVersion & "/libtls-client-darwin-amd64-" & TlsClientVersion & ".dylib"
  else: # linux
    when defined(amd64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & TlsClientVersion & "/libtls-client-linux-amd64-" & TlsClientVersion & ".so"
    elif defined(arm64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & TlsClientVersion & "/libtls-client-linux-arm64-" & TlsClientVersion & ".so"
    else:
      result = ""
      
# this checks if the shared library exists locally and ifits not downloads it automatically
proc ensureBinaryExists*(libPath: string) =
  let versionFilePath = libPath & ".version"
  let binaryExists = fileExists(libPath)

  # If the binary is already placed manually, automatically stamp it 
  # and skip downloading entirely.
  if binaryExists:
    if not fileExists(versionFilePath):
      try:
        writeFile(versionFilePath, TlsClientVersion)
        echo "[tls-client] Local binary detected. Automatically wrote version stamp: ", TlsClientVersion
      except:
        discard
    return
  
  var currentVersion = ""
  # read existing version metadata if present
  if fileExists(versionFilePath):
    try:
      currentVersion = readFile(versionFilePath).strip()
    except:
      currentVersion = ""

  # if binary exists and version matches then gud
  if currentVersion == TlsClientVersion:
    return

  let dir = parentDir(libPath)
  if dir.len > 0 and not dirExists(dir):
    createDir(dir)

  let url = getDownloadUrl()
  if url.len == 0:
    raise newException(IOError, "Unsupported platform or architecture for automatic tls-client binary download.")

  if binaryExists:
    echo "[tls-client] Updating local binary from version '", currentVersion, "' to '", TlsClientVersion, "'..."
  else:
    echo "[tls-client] Binary not found locally. Downloading release version ", TlsClientVersion, "..."
  
  echo "[tls-client] Source: ", url
  
  var httpClient = newHttpClient()
  try:
    httpClient.downloadFile(url, libPath)
    # write version stamp upon successful download
    writeFile(versionFilePath, TlsClientVersion)
    echo "[tls-client] Successfully updated library and version stamp to: ", TlsClientVersion
  except Exception as e:
    raise newException(IOError, "Failed to auto-download/update tls-client shared library: " & e.msg)
  finally:
    httpClient.close()

proc loadTlsClient*(libPath: string = defaultLibPath) =
  if lib != nil: return # already loaded

  # bootstrap the binary if missing before loading
  ensureBinaryExists(libPath)
  
  lib = loadLib(libPath)
  if lib == nil:
    raise newException(IOError, "Failed to load shared library from: " & libPath)
  
  let reqSym = lib.symAddr("request")
  if reqSym == nil:
    raise newException(OSError, "Symbol 'request' not found in library.")
  reqProc = cast[TlsRequestProc](reqSym)

  # bind destroySession if its available in the sl version
  let destroySym = lib.symAddr("destroySession")
  if destroySym != nil:
    destroyProc = cast[DestroySessionProc](destroySym)

  let freeSym = lib.symAddr("freeMemory")
  if freeSym != nil:
    freeProc = cast[FreeMemoryProc](freeSym)

proc executeRequest*(payloadJson: string): string =
  if reqProc == nil:
    raise newException(Defect, "TLS client bindings not initialized. Call loadTlsClient() first.")
  
  let cPayload = cstring(payloadJson)
  let cResponse = reqProc(cPayload)
  
  # copy the response string into Nim's managed memory space
  result = $cResponse

  # safely free the memory allocated by the go runtime
  if freeProc != nil and cResponse != nil:
    freeProc(cResponse)

# the executor for the destructor hooks
proc executeDestroySession*(sessionId: string) =
  if destroyProc == nil or sessionId.len == 0: return
  
  let payload = %* {"sessionId": sessionId}
  let cPayload = cstring($payload)
  let cResponse = destroyProc(cPayload)

  if freeProc != nil and cResponse != nil:
    freeProc(cResponse)
