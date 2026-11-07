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
const defaultLibPath* = 
  when defined(windows): "binaries/libtls-client.dll"
  elif defined(macosx): "binaries/libtls-client.dylib"
  else: "binaries/libtls-client.so"

# added a dynamic lib downloader for simplicity's sake so i and you don't want to manually source tls-client sl
# this maps the current os and cpu arch to the tls-client release binary
proc getDownloadUrl*(): string =
  let version = "v1.16.0" # target release version
  when defined(windows):
    when defined(amd64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & version & "/libtls-client-windows-amd64-" & version & ".dll"
    else:
      result = ""
  elif defined(macosx):
    when defined(arm64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & version & "/libtls-client-darwin-arm64-" & version & ".dylib"
    else:
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & version & "/libtls-client-darwin-amd64-" & version & ".dylib"
  else: # Linux
    when defined(amd64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & version & "/libtls-client-linux-amd64-" & version & ".so"
    elif defined(arm64):
      result = "https://github.com/bogdanfinn/tls-client/releases/download/" & version & "/libtls-client-linux-arm64-" & version & ".so"
    else:
      result = ""
      
# this checks if the shared library exists locally and ifits not downloads it automatically
proc ensureBinaryExists*(libPath: string) =
  if fileExists(libPath):
    return
  
  let dir = parentDir(libPath) # changed from extractFileDir to parentDir as that is what stdlib use
  if dir.len > 0 and not dirExists(dir):
    createDir(dir)

  let url = getDownloadUrl()
  if url.len == 0:
    raise newException(IOError, "Unsupported platform or architecture for automatic tls-client binary download.")

  echo "[tls-client] Binary not found locally. Downloading matching release..."
  echo "[tls-client] Source: ", url
  
  var httpClient = newHttpClient()
  try:
    httpClient.downloadFile(url, libPath)
    echo "[tls-client] Successfully downloaded library to: ", libPath
  except Exception as e:
    raise newException(IOError, "Failed to auto-download tls-client shared library: " & e.msg)
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
