---
name: coinglass-api-decrypt
description: Use when analyzing or decrypting encrypted CoinGlass web APIs, especially responses with encrypted data fields, response headers such as encryption/v/ev/user/time, request headers such as cache-ts-v2 and obe, or when asked to write Python/JavaScript scripts that fetch CoinGlass internal APIs and decode them to plaintext JSON.
---

# CoinGlass API Decrypt

Use this skill for CoinGlass web API responses that return encrypted payloads, commonly shaped like:

```json
{"code":"0","msg":"success","data":"<base64 ciphertext>","success":true}
```

The goal is to reproduce the browser frontend's decrypt path, not to guess fields.

## Quick Workflow

1. Ask for or capture the full browser curl, including request headers and response headers.
2. Preserve request headers exactly when possible. Current endpoints often require:

```text
language: zh
encryption: true
cache-ts-v2: <milliseconds timestamp>
obe: <browser-generated token>
Referer: https://www.coinglass.com/
User-Agent: browser UA
Accept: application/json
```

3. Confirm the response includes encrypted `data`. If it only returns `{"code":"0","msg":"success","success":true}`, the request is missing a required runtime header, usually `obe` or `cache-ts-v2`.
4. Inspect response headers. Important headers include:

```text
encryption
v
ev
user
time
```

5. Implement the decrypt chain for the detected version.

## Current v=0 / ev=2 Chain

This is the chain observed for:

```text
GET https://capi.coinglass.com/api/home/v2/coinMarkets
```

Request side:

```text
cache-ts-v2 = T
```

Key derivation:

```text
initialKey = base64(T).slice(0, 16)
```

Decrypt response header `user`:

```text
dataKeyGzip = AES-ECB-PKCS7-Decrypt(base64(user), initialKey)
dataKey = gzip_decompress(dataKeyGzip)
```

Decrypt response body `data`:

```text
plaintextGzip = AES-ECB-PKCS7-Decrypt(base64(data), dataKey)
plaintextJson = JSON.parse(gzip_decompress(plaintextGzip))
```

Expected output:

```json
{"total":857,"pageSize":20,"list":[...]}
```

## Algorithm Notes

- AES mode: `ECB`
- Padding: `PKCS7`
- Ciphertext encoding: base64
- Payload compression: gzip for the current v=0/ev=2 endpoints
- Older or alternate endpoints may decrypt to a hex string containing zlib-compressed bytes. Detect by checking whether decrypted bytes start with gzip magic `1f 8b`; otherwise try `bytes.fromhex(...)` then zlib inflate.
- Frontend uses CryptoJS style calls such as `CryptoJS.AES.decrypt(ciphertext, CryptoJS.enc.Utf8.parse(key), { mode: ECB, padding: Pkcs7 })`. Python `cryptography` works for 16/24/32-byte keys. If a CoinGlass branch uses non-standard CryptoJS WordArray key sizes, use or port the bundled script's CryptoJS-compatible AES helper.

## Script Starter

When the user asks for a script, output or create a Python script for the specific API being worked on. Name it after the API path, not generically. Convert `/api/home/v2/coinMarkets` to:

```text
api_home_v2_coinMarkets_decrypt.py
```

Use this naming convention:

```text
<api path without leading slash, slashes replaced by underscores>_decrypt.py
```

If query parameters identify the data variant, append the meaningful variant before `_decrypt.py`, for example:

```text
api_fundingRate_list_BTC_decrypt.py
```

Use `scripts/coinglass_decrypt.py` as the starting point/template when creating the endpoint-specific script. Typical command for the bundled example:

```bash
python scripts/coinglass_decrypt.py 1 --pretty
```

For a different CoinGlass endpoint:

- Change `COINGLASS_HOME_MARKETS_URL`
- Keep the browser curl headers aligned, especially `cache-ts-v2` and `obe`
- Keep `cache-ts-v2` stored with the response because it is required to decrypt header `user`
- If the response version changes, inspect the current frontend bundle and map the `v` branch before modifying key derivation
- Save the generated script with the endpoint-derived name, and include a short usage example in the final answer

## Frontend Inspection Hints

When the version changes, search the frontend chunks for:

```text
AES.decrypt
headers.encryption
headers.user
headers.time
cache-ts-v2
obe
```

If names are obfuscated, run only the string-decoder helper locally to reveal property names. Avoid relying on guessed field names.
