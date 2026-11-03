import std/[tables, json]
import ../src/tls_client

proc main() =
  # Initialize with a modern Chrome profile
  let client = newHttpClient(profile = cpChrome133)

  var headers = initTable[string, string]()
  headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
  headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
  headers["accept-language"] = "en-US,en;q=0.9"

  echo "Firing request to target fingerprint inspector..."
  let res = client.get("https://tls.peet.ws/api/all", headers)

  echo "Status Code: ", res.status
  echo "Response Body Length: ", res.body.len, " bytes"
  
  # Print parsed JSON snippets safely
  if res.rawJson.hasKey("tls_version"):
    echo "Negotiated TLS Version: ", res.rawJson["tls_version"].getStr()
  if res.rawJson.hasKey("ja3"):
    echo "JA3 Fingerprint: ", res.rawJson["ja3"].getStr()

main()
