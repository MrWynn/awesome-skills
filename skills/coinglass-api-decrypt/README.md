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

## Example Request

This is a typical captured browser request that can be used as input when
creating an endpoint-specific decrypt script:

```bash
curl 'https://capi.coinglass.com/api/futures/liquidation/chart?symbol=&timeType=10&range=1d' \
  -H 'accept: application/json' \
  -H 'accept-language: zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7' \
  -H 'cache-ts-v2: 1779334477963' \
  -H 'encryption: true' \
  -H 'language: zh' \
  -H 'obe: s_25cab7edd3ce4bca96c62e694e6e907d' \
  -H 'origin: https://www.coinglass.com' \
  -H 'priority: u=1, i' \
  -H 'referer: https://www.coinglass.com/' \
  -H 'sec-ch-ua: "Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' \
  -H 'sec-fetch-dest: empty' \
  -H 'sec-fetch-mode: cors' \
  -H 'sec-fetch-site: same-site' \
  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'
```

For this endpoint, an endpoint-specific script should follow the naming
convention:

```text
api_futures_liquidation_chart_decrypt.py
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
