import std/[strutils, random]

# added this to add proxy rotation and options support, this introduces a ProxyRotatot and a http3 proxy guard to prevent the common proxy trap
type
  ProxyType* = enum
    ptHttp, ptHttps, ptSocks4, ptSocks5, ptSocks5h, ptUnknown

  ProxyConfig* = object
    rawUrl*: string
    pType*: ProxyType

  RotationStrategy* = enum
    rsRoundRobin, rsRandom

  ProxyRotator* = ref object
    proxies*: seq[ProxyConfig]
    currentIndex*: int
    strategy*: RotationStrategy

proc parseProxyUrl*(proxyUrl: string): ProxyConfig =
  var pType = ptUnknown
  var cleanUrl = proxyUrl
  
  let lower = proxyUrl.toLowerAscii()
  if lower.startswith("socks5h://"):
    pType = ptSocks5h
  elif lower.startswith("socks5://"):
    pType = ptSocks5
  elif lower.startswith("socks4://"):
    pType = ptSocks4
  elif lower.startswith("https://"):
    pType = ptHttps
  elif lower.startswith("http://"):
    pType = ptHttp
  else:
    pType = ptHttp
    cleanUrl = "http://" & proxyUrl

  ProxyConfig(rawUrl: cleanUrl, pType: pType)

proc newProxyRotator*(proxyUrls: seq[string], strategy: RotationStrategy = rsRoundRobin): ProxyRotator =
  var configs: seq[ProxyConfig] = @[]
  for url in proxyUrls:
    configs.add(parseProxyUrl(url))
  ProxyRotator(
    proxies: configs,
    currentIndex: 0,
    strategy: strategy
  )

proc nextProxy*(rotator: ProxyRotator): string =
  if rotator == nil or rotator.proxies.len == 0: return ""
  
  let proxy = case rotator.strategy
    of rsRoundRobin:
      let p = rotator.proxies[rotator.currentIndex]
      rotator.currentIndex = (rotator.currentIndex + 1) mod rotator.proxies.len
      p
    of rsRandom:
      randomize()
      rotator.proxies[rand(rotator.proxies.len - 1)]
  
  result = proxy.rawUrl

# http3 proxy guard
proc ensureProxyHttp3Safe*(proxyConfig: ProxyConfig, enableHttp3: var bool) =
  # prevents ip leaks by validating if the proxy scheme supports udp
  # http3 requires socks5/socks5h with udp associate support
  if not enableHttp3: return

  if proxyConfig.pType in {ptHttp, ptHttps, ptSocks4}:
    echo "[tls-client warning] Incompatible proxy scheme for HTTP/3 (", proxyConfig.rawUrl, "). " &
         "HTTP/3 requires SOCKS5/SOCKS5h. Forcing fallback to HTTP/2 over TCP to prevent IP leaks."
    enableHttp3 = false # force safe downgrade
