import std/dynlib
import std/json

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

proc loadTlsClient*(libPath: string = defaultLibPath) =
  if lib != nil: return # already loaded
  
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
