# Lab 3: PoW Blockchain over IPv8

## Overview

You and your two teammates from Lab 2 build IPv8 nodes that together run a 3-node Proof-of-Work blockchain. Each member runs one node. Your nodes must mine blocks, propagate them, converge on a single chain, and answer queries from the Lab 3 server.

Once you register, the Lab 3 server joins your blockchain community, submits a test transaction, and walks every chain to check PoW, header linking, body commitment, and 3-way consistency. Your group passes the first time those checks all hold.

## Server

| Parameter | Value |
|---|---|
| Registration Community ID | `4c616233426c6f636b636861696e323032365057` (= ASCII `Lab3Blockchain2026PW`, 20 bytes / 40 hex) |
| Server public key | `4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6` (74 bytes / 148 hex) |
| Group size | 3 (same composition as Lab 2) |
| Required confirmations | 3 |
| Per-attempt timeout | 5 minutes |
| Deadline | `2026-06-12T23:59:59 UTC` |

Reach the server through IPv8 peer discovery on the registration community ID above. Filter peers by the published public key — never trust a peer whose key does not match.

## Prerequisites and deliverable

- Use the **same IPv8 key pair** each member used in Labs 1 and 2 — whatever key type you registered with (`curve25519`, `medium`, `high`, …). Signature verification on test transactions goes through `ECCrypto.key_from_public_bin()`, so any IPv8 key type works.
- Add your Lab 3 client code to the **same personal GitHub repository** each member registered in Lab 1.
- The deliverable is a working blockchain node. There is nothing to submit manually — the server records your group's pass, and you receive an email at the address from Lab 1 when it lands.

## Wire-level authentication

Send every message — to the server and to teammates — with IPv8's authenticated send (`ez_send` and friends). Each packet carries a `BinMemberAuthenticationPayload` with your public key and a signature over the payload. The server reads your key from this header to identify you. Unsigned packets are dropped silently.

## Part 1: Register your blockchain

Before grading, register your blockchain's community ID with the Lab 3 server on the **Registration Community**.

### Register Blockchain (message_id = 1)

Sent by any group member.

| Field | Type | Wire | Description |
|---|---|---|---|
| `group_id` | str | `varlenHutf8` | Your group ID from Lab 2 |
| `community_id` | bytes | `varlenH` | 20-byte community ID of your blockchain |

### Register Response (message_id = 2)

| Field | Type | Wire | Description |
|---|---|---|---|
| `success` | bool | `?` | True if registered |
| `message` | str | `varlenHutf8` | Human-readable result |

Once your registration is recorded, the server joins your blockchain community and runs a check within a few minutes. If your 3 nodes aren't fully online yet when the first attempt fires, the server retries automatically — **up to 3 retries per registration**. After that, automatic retries stop until you register again.

**Re-registering is allowed at any time** and resets the retry counter. Send `RegisterBlockchain` again to trigger a fresh batch of attempts. Re-registering with a different `community_id` replaces the recorded community for your group; subsequent attempts run against the new chain.

## Part 2: Respond to server queries

Inside **your** blockchain community (the one identified by the `community_id` you registered), your nodes implement handlers for the queries the server sends them.

### Submit Transaction (message_id = 1)

| Field | Type | Wire | Description |
|---|---|---|---|
| `sender_key` | bytes | `varlenH` | IPv8 public key of the signer |
| `data` | bytes | `varlenH` | Arbitrary payload bytes |
| `timestamp` | int | `q` | Unix timestamp |
| `signature` | bytes | `varlenH` | Signature over `sender_key + data + timestamp_8byte_be` |

Verify the signature, add the transaction to your mempool, and respond.

### Submit Transaction Response (message_id = 2)

| Field | Type | Wire | Description |
|---|---|---|---|
| `success` | bool | `?` | True if accepted into your mempool |
| `tx_hash` | bytes | `varlenH` | 32-byte transaction hash (formula in *Block format* below) |
| `message` | str | `varlenHutf8` | Human-readable result |

### Get Chain Height (message_id = 3)

| Field | Type | Wire | Description |
|---|---|---|---|
| `request_id` | int | `q` | Identifier for matching the response |

### Chain Height Response (message_id = 4)

| Field | Type | Wire | Description |
|---|---|---|---|
| `request_id` | int | `q` | Matching request identifier |
| `height` | int | `q` | Current chain height (genesis = 0) |
| `tip_hash` | bytes | `varlenH` | Hash of the latest block header |

### Get Block (message_id = 5)

| Field | Type | Wire | Description |
|---|---|---|---|
| `height` | int | `q` | Block height to fetch |

### Block Response (message_id = 6)

| Field | Type | Wire | Description |
|---|---|---|---|
| `height` | int | `q` | Block height |
| `prev_hash` | bytes | `varlenH` | Previous block hash (32 bytes) |
| `txs_hash` | bytes | `varlenH` | Commitment to the block's transactions (32 bytes) |
| `timestamp` | int | `q` | Block timestamp |
| `difficulty` | int | `q` | Declared difficulty in leading zero bits |
| `nonce` | int | `q` | PoW nonce |
| `block_hash` | bytes | `varlenH` | Hash of this block header (32 bytes) |
| `tx_hashes` | bytes | `varlenH` | Concatenated 32-byte transaction hashes, in block order. `b""` for an empty block. |

## Block format

### Header (84 bytes)

```
prev_hash    (32 bytes)
txs_hash     (32 bytes)
timestamp    ( 8 bytes, uint64 big-endian)
difficulty   ( 4 bytes, uint32 big-endian)
nonce        ( 8 bytes, uint64 big-endian)
```

`block_hash = SHA256(header_bytes)` over those 84 bytes, in that order. **PoW rule:** `block_hash` must have at least `difficulty` leading zero bits. Choose the value of `difficulty` for each block yourself; it's part of the header.

### Transaction hash

`tx_hash = SHA256(sender_key || data || timestamp_8byte_be || signature)`

### Body commitment

`txs_hash = SHA256(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)` over the block's transactions in the order they appear. An empty block uses `txs_hash = SHA256(b"")`.

When the server fetches a block, it splits `tx_hashes` into 32-byte chunks, recomputes the SHA-256 over the concatenation, and confirms it matches the header's `txs_hash`.

## Consensus

Your 3 nodes must converge on a single chain. The longest chain rule is the canonical answer: when a block arrives, validate it (PoW satisfies its declared `difficulty`, `prev_hash` links cleanly, `txs_hash` matches the body), then append, fork-switch, or ignore depending on whether it extends, overtakes, or stays behind your current tip.

How you detect, fetch, and apply forks is your design call. The server only requires that all 3 nodes agree on the same chain.

## Grading

Pass/fail. The server records the outcome the first time your group's chain clears every check below. Once recorded, the pass is sticky — re-registering after passing doesn't undo it. Submissions after the deadline are flagged late.

Each check is over the chain returned by your 3 nodes during one attempt:

- **Transaction accepted.** The node receiving the server's Submit Transaction returns `success = True`.
- **Chain integrity.** Every block has a valid PoW for its declared `difficulty`, and `prev_hash` of each block matches its parent's `block_hash`.
- **Body commitment.** Recomputed `SHA256(tx_hash_1 || ... || tx_hash_n)` over the test transaction's block matches that block's `txs_hash`.
- **Confirmations.** The test transaction is buried under at least 3 blocks on every node.
- **Consistency.** All 3 nodes agree on the same `block_hash` at every confirmed height.

Each attempt requires all 3 of your nodes to be online and reachable for its duration (around 5 minutes). With automatic retries (up to 3 per registration) plus unlimited re-registration, you don't need to be online at any specific moment — just keep your nodes running until you receive the pass email.

## Tips

- Build the chain primitives first (block header packing, hashing, PoW search, the flat `txs_hash` commitment) and unit-test them before introducing peers.
- Get single-node mining and chain validation working before you wire up propagation.
- All 3 of your nodes must agree on the same chain at every height — including the very first block. Pick a within-group convention for what your block 0 looks like and make sure every node boots up with it.

## Common pitfalls

- Encoding `timestamp`, `difficulty`, or `nonce` in the wrong byte order or width.
- Hashing the text form of an integer instead of its big-endian binary form.
- Forgetting that `txs_hash` for an empty block is `SHA256(b"")`, not 32 zero bytes.
- Three nodes that mine independently but don't propagate cleanly, leaving each on its own private chain, i.e., the consistency check fails immediately.
- Registering before all 3 nodes are reachable; the first attempt fails with no inclusion. Just re-register once they're up.
- Accepting any peer in the community as the server instead of filtering by the published public key.