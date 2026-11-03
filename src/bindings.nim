import std/dynlib

type
  TlsRequestProc = proc(rawPayload: cstring): cstring {.cdecl, gcsafe.}
  FreeMemoryProc = proc(rawPayload: cstring) {.cdecl, gcsafe.}

var
  lib: LibHandle
  reqProc: TlsRequestProc
  freeProc: FreeMemoryProc

proc loadTlsClient*(libPath: string = "./binaries/libtls-client.so") =
  if lib != nil: return # already loaded
  
  lib = loadLib(libPath)
  if lib == nil:
    raise newException(IOError, "Failed to load shared library from: " & libPath)
  
  let reqSym = lib.symAddr("request")
  if reqSym == nil:
    raise newException(OSError, "Symbol 'request' not found in library.")
  reqProc = cast[TlsRequestProc](reqSym)

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
