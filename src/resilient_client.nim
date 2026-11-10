import std/[json, tables, strutils, times, asyncdispatch, random, os]
import ./tls_client
import ./proxy_manager

type
  ProxyHealth* = ref object
    rawUrl*: string
    consecutiveFailures*: int
    successCount*: int
    cooldownUntil*: float  # unix epoch timestamp until which the proxy is quarantined

  ResilientRotator* = ref object
    proxies*: seq[ProxyHealth]
    currentIndex*: int
    strategy*: RotationStrategy
    maxFailures*: int        # failures before triggering a cooldown quarantine
    cooldownSeconds*: float  # duration of the quarantine window

  ResilientClient* = ref object
    client*: HttpClient
    rotator*: ResilientRotator
    maxRetries*: int
    baseBackoffMs*: int

proc newResilientRotator*(
    proxyUrls: seq[string], 
    strategy: RotationStrategy = rsRoundRobin,
    maxFailures: int = 3,
    cooldownSeconds: float = 60.0
): ResilientRotator =
  var healthSeq: seq[ProxyHealth] = @[]
  for url in proxyUrls:
    healthSeq.add(ProxyHealth(
      rawUrl: url,
      consecutiveFailures: 0,
      successCount: 0,
      cooldownUntil: 0.0
    ))
  ResilientRotator(
    proxies: healthSeq,
    currentIndex: 0,
    strategy: strategy,
    maxFailures: maxFailures,
    cooldownSeconds: cooldownSeconds
  )

proc getNextHealthyProxy*(rotator: ResilientRotator): string =
  if rotator == nil or rotator.proxies.len == 0: return ""
  
  let now = epochTime()
  var checkedCount = 0
  let totalProxies = rotator.proxies.len

  while checkedCount < totalProxies:
    let idx = case rotator.strategy
      of rsRoundRobin:
        let pIdx = rotator.currentIndex
        rotator.currentIndex = (rotator.currentIndex + 1) mod totalProxies
        pIdx
      of rsRandom:
        randomize()
        rand(totalProxies - 1)

    let proxyHealth = rotator.proxies[idx]
    
    # check if proxy is currently in cooldown quarantine
    if proxyHealth.cooldownUntil <= now:
      return proxyHealth.rawUrl
      
    checkedCount.inc

  # fallback: if all proxies are cooling down, return the one whose cooldown expires soonest
  var bestProxy = rotator.proxies[0]
  for p in rotator.proxies:
    if p.cooldownUntil < bestProxy.cooldownUntil:
      bestProxy = p

  echo "[tls-client warning] All proxies are currently in cooldown. Re-using proxy with earliest recovery: ", bestProxy.rawUrl
  return bestProxy.rawUrl

proc markFailure*(rotator: ResilientRotator, proxyUrl: string) =
  if proxyUrl.len == 0: return
  let now = epochTime()
  for p in rotator.proxies:
    if p.rawUrl == proxyUrl:
      p.consecutiveFailures.inc
      p.successCount = 0
      if p.consecutiveFailures >= rotator.maxFailures:
        p.cooldownUntil = now + rotator.cooldownSeconds
        echo "[tls-client quarantine] Proxy quarantined for ", rotator.cooldownSeconds, "s due to failures: ", proxyUrl
      break

proc markSuccess*(rotator: ResilientRotator, proxyUrl: string) =
  if proxyUrl.len == 0: return
  for p in rotator.proxies:
    if p.rawUrl == proxyUrl:
      p.consecutiveFailures = 0
      p.successCount.inc
      p.cooldownUntil = 0.0 # clear quarantine on success
      break

proc newResilientClient*(
    client: HttpClient,
    proxyPool: seq[string],
    maxRetries: int = 3,
    baseBackoffMs: int = 1000,
    maxFailures: int = 3,
    cooldownSeconds: float = 60.0
): ResilientClient =
  let rotator = newResilientRotator(proxyPool, rsRoundRobin, maxFailures, cooldownSeconds)
  let initialProxy = rotator.getNextHealthyProxy()
  
  if initialProxy.len > 0:
    client.currentProxy = initialProxy

  ResilientClient(
    client: client,
    rotator: rotator,
    maxRetries: maxRetries,
    baseBackoffMs: baseBackoffMs
  )

proc requestWithRetry*(
    rc: ResilientClient,
    httpMethod: string,
    url: string,
    headers: Table[string, string] = initTable[string, string](),
    body: string = ""
): Response =
  var attempt = 0
  
  while attempt <= rc.maxRetries:
    let activeProxy = rc.rotator.getNextHealthyProxy()
    rc.client.currentProxy = activeProxy

    try:
      let resp = rc.client.request(httpMethod, url, headers, body)
      
      # handle rate limiting (429) or blocks (403, 503)
      if resp.status in [429, 403, 503]:
        echo "[tls-client adaptive] Triggered status code ", resp.status, " on proxy: ", activeProxy
        rc.rotator.markFailure(activeProxy)
        attempt.inc
        if attempt > rc.maxRetries:
          return resp # return final rate-limited response if out of retries
        
        # exponential backoff with jitter
        let backoff = rc.baseBackoffMs * (1 shl (attempt - 1))
        os.sleep(backoff)
        continue

      # success path
      rc.rotator.markSuccess(activeProxy)
      return resp

    except Exception as e:
      echo "[tls-client error] Network exception on proxy ", activeProxy, ": ", e.msg
      rc.rotator.markFailure(activeProxy)
      attempt.inc
      if attempt > rc.maxRetries:
        raise e
      
      let backoff = rc.baseBackoffMs * (1 shl (attempt - 1))
      os.sleep(backoff)

  raise newException(IOError, "Max retries exceeded across all available proxies.")
