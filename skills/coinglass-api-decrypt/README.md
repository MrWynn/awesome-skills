# CoinGlass API Decrypt

`coinglass-api-decrypt` helps analyze and decrypt encrypted CoinGlass web API
responses, especially payloads shaped like:

```json
{"code":"0","msg":"success","data":"<base64 ciphertext>","success":true}
```

The skill focuses on reproducing the browser frontend decrypt path from captured
requests and responses.

## When To Use

Use this skill when working with CoinGlass internal web APIs that include:

- Encrypted `data` response fields
- Response headers such as `encryption`, `v`, `ev`, `user`, or `time`
- Request headers such as `cache-ts-v2` and `obe`
- Browser-only API behavior that needs to be reproduced in Python or JavaScript

## Files

- `SKILL.md`: Codex skill instructions and workflow
- `scripts/coinglass_decrypt.py`: Starter script for fetching and decrypting a
  known CoinGlass endpoint

## Quick Start

From this skill directory:

```bash
python scripts/coinglass_decrypt.py 1 --pretty
```

The bundled script targets:

```text
https://capi.coinglass.com/api/home/v2/coinMarkets
```

## Required Request Context

For reliable decryption, capture the full browser request and response context.
Important request headers commonly include:

```text
language: zh
encryption: true
cache-ts-v2: <milliseconds timestamp>
obe: <browser-generated token>
Referer: https://www.coinglass.com/
User-Agent: browser UA
Accept: application/json
```

Important response headers commonly include:

```text
encryption
v
ev
user
time
```

If the API returns only `{"code":"0","msg":"success","success":true}`, the
request is usually missing a runtime header such as `obe` or `cache-ts-v2`.

## Current Decrypt Chain

For currently observed `v=0` / `ev=2` responses:

```text
initialKey = base64(cache-ts-v2).slice(0, 16)
dataKeyGzip = AES-ECB-PKCS7-Decrypt(base64(user), initialKey)
dataKey = gzip_decompress(dataKeyGzip)
plaintextGzip = AES-ECB-PKCS7-Decrypt(base64(data), dataKey)
plaintextJson = JSON.parse(gzip_decompress(plaintextGzip))
```

Algorithm notes:

- AES mode: `ECB`
- Padding: `PKCS7`
- Ciphertext encoding: base64
- Payload compression: gzip for the current `v=0` / `ev=2` endpoints
- Alternate endpoints may use a hex string containing zlib-compressed bytes

## Creating Endpoint-Specific Scripts

When adapting the starter script for a new endpoint, name the script after the
API path:

```text
<api path without leading slash, slashes replaced by underscores>_decrypt.py
```

Example:

```text
/api/home/v2/coinMarkets -> api_home_v2_coinMarkets_decrypt.py
```

If query parameters identify the data variant, append the meaningful variant
before `_decrypt.py`, for example:

```text
api_fundingRate_list_BTC_decrypt.py
```
