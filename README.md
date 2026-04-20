## DON Secrets Utility (Python)

Many developers using Python + Solidity face a common problem: interacting with Chainlink DON requires JavaScript and the Chainlink Functions Toolkit.

This tool solves that problem by providing a Python-only solution for uploading secrets to Chainlink DON.

No Node.js, no JavaScript, no extra dependencies.

- **`encrypt_secrets.py`**: create `encryptedSecretsHexstring` (sign → ECIES → TDH2)
- **`upload_don_secrets.py`**: upload secrets to Functions gateways (`secrets_set`)


## Quick start (terminal scripts)

### 1) Install deps

```bash
cd don_secrets_utility
python -m venv .venv
```

- **macOS / Linux**:

```bash
source .venv/bin/activate
```

- **Windows (PowerShell)**:

```powershell
.venv\Scripts\Activate.ps1
```

Install base deps (upload):

```bash
pip install -U pip
pip install -r requirements.txt
```

If you want **encryption** too:

```bash
pip install -r requirements-encrypt.txt
```

### 2) Configure `.env`

```bash
cp .env.example .env
```

If `.env` is missing (or vars are missing), you can pass flags instead.

### 3) Encrypt

Create `secrets.json`:

```json
{
  "AUTHORIZATION": "Bearer <token>"
}
```

Run:

```bash
python encrypt_secrets.py --secrets-json secrets.json
```

This writes `enc_artifacts.encrypted_secrets.hex.txt` by default and prints the hex string.

### 4) Upload

```bash
python upload_don_secrets.py \
  --slot-id 1 \
  --encrypted-secrets-hex enc_artifacts.encrypted_secrets.hex.txt \
  --debug
```

Output looks like:

```json
{
  "version": 1776192355,
  "success": true,
  "gatewayUrl": "https://01.functions-gateway.testnet.chain.link/",
  "nodeResponses": [{ "success": true, "error_message": null }]
}
```

When `--debug` is enabled, it also prints a **copy/paste curl command**:
- POSIX shell (macOS/Linux)
- PowerShell (Windows)

## Quick start (library)

You can use the same code in your own Python project by importing from `lib/`.

### Upload from Python code

```python
from lib.uploader import upload_encrypted_secrets_to_don, DEFAULT_GATEWAY_URLS

result = upload_encrypted_secrets_to_don(
    private_key_hex="0x...",
    don_id="fun-ethereum-sepolia-1",
    gateway_urls=DEFAULT_GATEWAY_URLS,
    slot_id=1,
    encrypted_secrets_hex_or_path="enc_artifacts.encrypted_secrets.hex.txt",
    minutes_until_expiration=60,
    debug=True,
)

print(result["version"], result["success"])
```

### Encrypt from Python code

```python
from lib.encrypt import encrypt_secrets

artifacts = encrypt_secrets(
    secrets_json_path="secrets.json",
    private_key_hex="0x...",
    rpc_url="https://sepolia.infura.io/v3/<KEY>",
    functions_router_address="0xb83E47C2bC239B3bf370bc41e1459A34b41238D0",
    don_id="fun-ethereum-sepolia-1",
    out_prefix="enc_artifacts",
)

print(artifacts.encrypted_secrets_hex)
```

Note: encryption requires: `pip install -r requirements-encrypt.txt`.

## What is this for?

Chainlink Functions lets your on-chain consumer reference **DON-hosted secrets** via:
`req.addDONHostedSecrets(slotId, version)`.

Use this tool if you:

- Build smart contracts with Solidity and Python (Brownie, web3.py)
- Want to interact with Chainlink DON without JavaScript
- Need to upload secrets to Chainlink Functions
- Prefer Python-based blockchain development workflows
- Want to avoid Node.js and JS dependency overhead


This project helps you:
1) generate the encrypted payload (`encryptedSecretsHexstring`)
2) upload it to the DON storage (slot/version)

So you can avoid the JS toolkit when you prefer Python-only tooling.

## Common issues

- `sender not allowlisted`: wrong wallet key (not subscription owner) or invalid signature/body.
- `version too low`: that slot already has a newer version → use another `slot_id` or don’t fix `--version`.
- `failed to fetch DONHosted secrets: not found` (during Functions execution): your contract uses a `(slotId, version)` that doesn’t exist on the DON.

## Support the project

If this repo saved you some time, I’d love it if you:
- **Star** the repo on GitHub
- Buy me a donut (I really do love donuts)

ETH tip jar:
`0x7cb23658373178282CD716A230e5dd4f63a8efAF`

