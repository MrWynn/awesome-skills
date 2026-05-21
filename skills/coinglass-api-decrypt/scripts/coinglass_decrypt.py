#!/usr/bin/env python3
"""
Fetch and decrypt CoinGlass web API responses.

The CoinGlass frontend decrypts encrypted responses in its axios response
interceptor. The important path is:

    AES-ECB/PKCS7 decrypt -> hex bytes -> zlib inflate -> UTF-8 -> JSON

Usage examples:

    python coinglass_decrypt.py 1 --pretty

    python coinglass_decrypt.py --pageNum 2 --pageSize 20 --pretty

Advanced: decrypt a captured response body and headers:
    Get-Content response.json | python coinglass_decrypt.py --headers headers.json --url "https://capi.coinglass.com/api/home/v2/coinMarkets"

headers.json can be either a plain header object or a browser export object that
contains a "headers" object.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
import time
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


STATIC_KEY_V55 = "170b070da9654622"
COINGLASS_HOME_MARKETS_URL = "https://capi.coinglass.com/api/home/v2/coinMarkets"
DEFAULT_OBE = "s_25cab7edd3ce4bca96c62e694e6e907d"


class DecodeError(RuntimeError):
    pass


SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC]


def xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p & 0xFF


def sub_word(word: int) -> int:
    return (
        (SBOX[(word >> 24) & 0xFF] << 24)
        | (SBOX[(word >> 16) & 0xFF] << 16)
        | (SBOX[(word >> 8) & 0xFF] << 8)
        | SBOX[word & 0xFF]
    )


def rot_word(word: int) -> int:
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF


def cryptojs_key_schedule(key: bytes) -> tuple[list[int], int]:
    if len(key) % 4 != 0 or len(key) < 16:
        raise DecodeError(f"CryptoJS-compatible AES key must be a multiple of 4 bytes and at least 16 bytes, got {len(key)}.")
    key_words = [int.from_bytes(key[i : i + 4], "big") for i in range(0, len(key), 4)]
    key_size = len(key_words)
    n_rounds = key_size + 6
    ks_rows = (n_rounds + 1) * 4
    schedule = key_words[:]
    for row in range(key_size, ks_rows):
        temp = schedule[row - 1]
        if row % key_size == 0:
            temp = sub_word(rot_word(temp)) ^ (RCON[row // key_size] << 24)
        elif key_size > 6 and row % key_size == 4:
            temp = sub_word(temp)
        schedule.append((schedule[row - key_size] ^ temp) & 0xFFFFFFFF)
    return schedule, n_rounds


def add_round_key(state: list[list[int]], schedule: list[int], round_no: int) -> None:
    for col in range(4):
        word = schedule[round_no * 4 + col]
        state[0][col] ^= (word >> 24) & 0xFF
        state[1][col] ^= (word >> 16) & 0xFF
        state[2][col] ^= (word >> 8) & 0xFF
        state[3][col] ^= word & 0xFF


def inv_shift_rows(state: list[list[int]]) -> None:
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def inv_sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]


def inv_mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        state[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        state[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        state[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)


def cryptojs_aes_ecb_decrypt(encrypted: bytes, key: bytes) -> bytes:
    schedule, n_rounds = cryptojs_key_schedule(key)
    out = bytearray()
    for block_start in range(0, len(encrypted), 16):
        block = encrypted[block_start : block_start + 16]
        if len(block) != 16:
            raise DecodeError("Ciphertext length is not a multiple of AES block size.")
        state = [[block[4 * c + r] for c in range(4)] for r in range(4)]
        add_round_key(state, schedule, n_rounds)
        for round_no in range(n_rounds - 1, 0, -1):
            inv_shift_rows(state)
            inv_sub_bytes(state)
            add_round_key(state, schedule, round_no)
            inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, schedule, 0)
        out.extend(state[r][c] for c in range(4) for r in range(4))
    return bytes(out)


def load_json(path: str | None) -> Any:
    try:
        raw = sys.stdin.read() if not path or path == "-" else Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise DecodeError(f"File not found: {path}") from exc
    except OSError as exc:
        raise DecodeError(f"Could not read {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DecodeError(f"Invalid JSON input: {exc}") from exc


def normalize_headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict) and isinstance(value.get("headers"), dict):
        value = value["headers"]
    if not isinstance(value, dict):
        raise DecodeError("Headers must be a JSON object.")
    return {str(k).lower(): str(v) for k, v in value.items()}


def get_header(headers: dict[str, str], name: str) -> str:
    try:
        return headers[name.lower()]
    except KeyError as exc:
        raise DecodeError(f"Missing response header: {name}") from exc


def strip_api_prefix(url: str) -> str:
    """
    Frontend helper `ne()` strips `/api` and any query string from the URL.
    This is used only when body.user.v == "1".
    """
    path = urlsplit(url).path or url
    marker = "/api"
    if marker in path:
        path = path[path.index(marker) + len(marker) :]
    return path.split("?", 1)[0]


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise DecodeError("AES decrypted to empty bytes.")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecodeError("Invalid PKCS7 padding. The key or ciphertext is probably wrong.")
    return data[:-pad]


def aes_ecb_pkcs7_decrypt_base64(ciphertext: str, key_text: str) -> bytes:
    try:
        encrypted = base64.b64decode(ciphertext)
    except binascii.Error as exc:
        raise DecodeError("Ciphertext is not valid base64.") from exc

    key = key_text.encode("utf-8")
    if len(key) in (16, 24, 32):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
    else:
        padded = cryptojs_aes_ecb_decrypt(encrypted, key)
    return pkcs7_unpad(padded)


def inflate_hex_payload(hex_text: bytes) -> str:
    if hex_text.startswith(b"\x1f\x8b"):
        try:
            return zlib.decompress(hex_text, 16 + zlib.MAX_WBITS).decode("utf-8")
        except zlib.error as exc:
            raise DecodeError("Gzip inflate failed.") from exc

    try:
        compressed = bytes.fromhex(hex_text.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DecodeError("AES plaintext is neither gzip data nor a hex string.") from exc

    try:
        return zlib.decompress(compressed).decode("utf-8")
    except zlib.error as exc:
        raise DecodeError("Inflate failed. The decrypted payload is not zlib-compressed data.") from exc


def decrypt_field(ciphertext: str, key_text: str) -> str:
    plaintext_hex = aes_ecb_pkcs7_decrypt_base64(ciphertext, key_text)
    text = inflate_hex_payload(plaintext_hex)
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text


def get_user_object(body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    user = body.get("user")
    if isinstance(user, dict):
        return user

    header_user = headers.get("user")
    if header_user:
        try:
            parsed = json.loads(header_user)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"secret": header_user}

    return {}


def derive_initial_key(body: dict[str, Any], headers: dict[str, str], url: str | None) -> str:
    user = get_user_object(body, headers)

    version = str(headers.get("v") or user.get("v") or "")
    if version == "0":
        secret = headers.get("_request-cache-ts-v2") or user.get("secret") or user.get("s")
        if not secret:
            raise DecodeError('response v is "0", but no cache-ts-v2 request value was recorded.')
        seed = str(secret)
    elif version == "1":
        if not url:
            raise DecodeError('response v is "1"; pass --url so the URL-derived key can be built.')
        seed = strip_api_prefix(url)
    elif version == "2":
        seed = get_header(headers, "time")
    elif version == "55":
        seed = STATIC_KEY_V55
    elif version in {"66", "77"}:
        raise DecodeError(
            f'response v "{version}" uses a static key hidden in the current obfuscated bundle. '
            "This script supports v=0, v=1, v=2, and v=55."
        )
    else:
        raise DecodeError(
            f"Unsupported or missing response v value: {version!r}. "
            "Save/pass the response headers; the data body alone is not enough."
        )

    encoded = base64.b64encode(seed.encode("utf-8")).decode("ascii")
    return encoded[:16] if version == "0" else encoded


def decrypt_response(body: dict[str, Any], headers: dict[str, str], url: str | None) -> Any:
    if not isinstance(body, dict):
        raise DecodeError("Response body must be a JSON object.")
    if "data" not in body:
        return body

    initial_key = derive_initial_key(body, headers, url)
    if str(headers.get("v", "")) == "0":
        final_key = decrypt_field(get_header(headers, "user"), initial_key)
    else:
        final_key = decrypt_field(get_header(headers, "time"), initial_key)
    plaintext = decrypt_field(str(body["data"]), final_key)

    try:
        return json.loads(plaintext)
    except json.JSONDecodeError:
        return plaintext


def build_markets_url(page_num: int, page_size: int) -> str:
    query = urlencode(
        {
            "pageNum": page_num,
            "pageSize": page_size,
            "sort": "",
            "order": "",
            "keyword": "",
            "ex": "all",
        }
    )
    return f"{COINGLASS_HOME_MARKETS_URL}?{query}"


def fetch_json(url: str, obe: str) -> tuple[dict[str, Any], dict[str, str]]:
    cache_ts_v2 = str(int(time.time() * 1000))
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://www.coinglass.com/",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/148.0.0.0 Safari/537.36"
        ),
        "cache-ts-v2": cache_ts_v2,
        "encryption": "true",
        "language": "zh",
        "obe": obe,
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            response_headers = normalize_headers(dict(response.headers.items()))
            response_headers["_request-cache-ts-v2"] = cache_ts_v2
    except OSError as exc:
        raise DecodeError(f"Request failed: {exc}") from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DecodeError(f"Response is not valid JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise DecodeError("Response JSON is not an object.")
    return body, response_headers


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and decrypt CoinGlass home market data.")
    parser.add_argument("pageNum", nargs="?", type=int, help="Page number to fetch, for example: 1")
    parser.add_argument("--pageNum", dest="page_num_flag", type=int, help="Page number to fetch.")
    parser.add_argument("--pageSize", type=int, default=20, help="Page size. Default: 20")
    parser.add_argument("--obe", default=DEFAULT_OBE, help="CoinGlass obe request header.")
    parser.add_argument("--body", "-b", help="Advanced: response body JSON file. Use '-' to read stdin.")
    parser.add_argument("--headers", "-H", help="Advanced: response headers JSON file.")
    parser.add_argument("--url", help="Advanced: original request URL.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args()

    try:
        if args.headers:
            body = load_json(args.body)
            headers = normalize_headers(load_json(args.headers))
            result = decrypt_response(body, headers, args.url)
        else:
            page_num = args.page_num_flag or args.pageNum
            if page_num is None:
                raise DecodeError("Please pass a page number, for example: python coinglass_decrypt.py 1")
            if page_num < 1:
                raise DecodeError("pageNum must be >= 1.")
            if args.pageSize < 1:
                raise DecodeError("pageSize must be >= 1.")
            url = build_markets_url(page_num, args.pageSize)
            body, headers = fetch_json(url, args.obe)
            result = decrypt_response(body, headers, url)
    except DecodeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if isinstance(result, (dict, list)):
        print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
