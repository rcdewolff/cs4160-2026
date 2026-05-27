# Lab 1: Proof of Work over IPv8

## Overview

In this assignment, you will build an IPv8 client **from scratch** that:

1. Connects to a running server via the IPv8 peer-to-peer network
2. Computes a Proof of Work (PoW) over your email **and** your GitHub repo URL
3. Submits the solution as an IPv8 message
4. Receives a response from the server (accepted or rejected)

Your public key is registered on the server upon success. **You are responsible for preserving your private key** (`.pem` file) — it is your identity for the rest of the course. If you do lose it before the deadline, the server allows re-registration with a fresh key against your existing email (see below), so you won't be locked out. Avoid this if you can. **After the deadline, the server is taken offline — no further submissions or re-registrations are possible.**

## Server Information

| Parameter | Value |
|-----------|-------|
| Community ID | `2c1cc6e35ff484f99ebdfb6108477783c0102881` (20 bytes / 40 hex) |
| Server Public Key | `4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb` (74 bytes / 148 hex) |
| Difficulty | 28 leading zero bits |
| Deadline | `2026-05-12T23:59:59 UTC` — after this time the server is shut down and no further submissions are possible |

You reach the server through IPv8's standard peer-discovery mechanism (see the [py-ipv8 documentation](https://py-ipv8.readthedocs.io/)). Join the community using the `community_id` above, and IPv8 will find peers in the community; your client then picks out the server from among them by matching the public key above.

**Verify the server before trusting responses.** Other peers in the community (e.g., your classmates' clients) will also be discoverable. Your client must filter peers by the server's public key; do not send your submission to, or accept responses from, peers whose public key doesn't match.

## Requirements

- Python 3.10+
- py-ipv8 library: https://github.com/Tribler/py-ipv8
- Read the py-ipv8 documentation: https://py-ipv8.readthedocs.io/
- A **public GitHub repository** containing the source code of your client. The URL of this repo is part of your submission, and changing it later requires re-solving the PoW. Course staff may review this repository during grading; make sure it contains the full source of the client you used to submit.

## Proof of Work

### The Challenge

Find a nonce (non-negative integer) such that:

```
SHA256( email_utf8 || "\n" || github_url_utf8 || "\n" || nonce_as_8_byte_big_endian )
```

has at least **28 leading zero bits** (i.e., the first 3 bytes are all zeros *and* the next byte is < 16).

`||` means byte concatenation. `"\n"` is the single ASCII newline byte (`0x0A`) used as a field separator. Neither your email nor your URL may contain a newline.

### Hash Computation

The hash input is, in order:

1. Your official TU Delft student email address, encoded as UTF-8 bytes. Must end in `@tudelft.nl` or `@student.tudelft.nl` and be ≤ 254 bytes. The address is canonicalised for identity purposes (NFC, whitespace stripped, lowercased), but the PoW hash is verified against the exact bytes you submit — whatever you hash locally is what the server will hash.
2. A single `\n` byte.
3. The URL of your public GitHub repo for this lab, encoded as UTF-8 bytes. Must be non-empty, ≤ 512 bytes, and contain no whitespace or control characters. The server does **not** verify that the URL resolves or that the repository is reachable — that is your responsibility.
4. A single `\n` byte.
5. Your nonce, encoded as a **64-bit big-endian integer** (8 bytes). The wire format on the payload is a signed int64 (struct code `q`), but valid nonces are non-negative; i.e., `0 ≤ nonce ≤ 2^63 − 1`. Negative values will be rejected by the server.

With 28-bit difficulty, you should expect to try approximately 2^28 (~268 million) nonces before finding a valid one — typically 2–3 minutes on a laptop with an optimised loop, 5–8 minutes with a naive one. PoW search is a geometric process with high variance: on an unlucky run you may need 10–20 minutes even on fast hardware, so design your system to survive a long search (don't time out your own mining loop, persist progress if you can). **Any optimisations are very welcome.**

### Wire Protocol

Once you find a valid nonce, send it to the server as an IPv8 message.

#### Submission Message (message_id = 1)

| Field        | Logical Type | IPv8 Wire Format | Description |
|--------------|--------------|------------------|-------------|
| `email`      | UTF-8 string | `varlenHutf8`    | Your TU Delft email address |
| `github_url` | UTF-8 string | `varlenHutf8`    | URL of your public GitHub repo |
| `nonce`      | integer      | `q`              | The nonce that solves the PoW |

#### Server Response (message_id = 2)

| Field     | Logical Type | IPv8 Wire Format | Description |
|-----------|--------------|------------------|-------------|
| `success` | boolean      | `?`              | `True` if your submission is accepted |
| `message` | UTF-8 string | `varlenHutf8`    | Human-readable result |

Both messages are authenticated using IPv8's `BinMemberAuthenticationPayload`. Your public key is automatically included and verified by IPv8 authentication; it is not part of the message payload.

#### Server Responses

| Response | Meaning |
|----------|---------|
| `success=True, message="Accepted"` | Your PoW is valid, you are registered |
| `success=True, message="Accepted (already registered)"` | Same (email, key, URL) resubmission — you already passed |
| `success=True, message="Accepted (github URL updated)"` | Same key and email, new URL with a fresh valid PoW |
| `success=True, message="Accepted (re-registered with new key)"` | Same email, new key — e.g., a lost-key recovery |
| `success=False, message="Rejected: invalid hash — need 28 leading zero bits, got N"` | Your hash doesn't meet the difficulty |
| `success=False, message="Rejected: this public key is already registered with a different email"` | You can only use one email per key |
| `success=False, message="Rejected: email must be a well-formed TU Delft address ..."` | Email is empty, malformed, or the domain is not `tudelft.nl` / `student.tudelft.nl` |
| `success=False, message="Rejected: github_url must be non-empty, ≤ 512 chars, and contain no whitespace/control chars"` | GitHub URL field failed validation |
| `success=False, message="Rejected: nonce must be a non-negative integer that fits in 63 bits"` | Nonce is negative or ≥ 2^63 |
| `success=False, message="Rejected: malformed submission payload ..."` | Packet reached the server but fields couldn't be decoded as `(email: string, github_url: string, nonce: int64)` |

### Policy on Identity Changes

- **One email per public key.** Once you register with an email, that email is permanently bound to your key. Submitting the same key with a different email is rejected.
- **Changing the GitHub URL (before the deadline).** Submit the same (email, key) with the new URL and a fresh valid PoW over that URL; the server will reply `Accepted (github URL updated)`.
- **Lost-key re-registration (before the deadline).** If you lose your `.pem`, you may submit a fresh key with the same email and a valid PoW; the server will reply `Accepted (re-registered with new key)`.
- **After the deadline.** The server is stopped at `2026-05-12T23:59:59 UTC`. Submissions, URL edits, and re-registrations are all impossible once that happens.

## Grading

- **Pass/fail.** The server either has your public key registered as passed by the deadline, or it doesn't.
- **Deadline: `2026-05-12T23:59:59 UTC`.** After this time the server is stopped; no further submissions are possible.

## Tips

- Start by reading the py-ipv8 overlay tutorials. Understand how communities, messages, and peer discovery work before writing code.
- Test your PoW computation locally before trying to send anything over the network.
- Decide your GitHub URL **before** mining. Mining a nonce binds you to that specific URL string; changing even a trailing `/` will invalidate the hash and require mining again.
- Use `curve25519` as your key generation type (IPv8 default).
- Your client must register a handler for the response message (`message_id = 2`) so it can receive the server's reply.
- The server verifies the sender's identity via IPv8's built-in message authentication. You do not need to include your public key in the message payload.
- If you get "invalid hash" responses, double-check your hash construction matches the spec exactly: UTF-8 encoding for both strings, `\n` separators, 8-byte big-endian nonce, SHA-256.
- If you get no response at all (timeout), the most likely cause is that your packet isn't being properly signed by IPv8 — unsigned or wrongly-signed packets are dropped without a reply. Make sure your client uses IPv8's standard authenticated send (e.g. `ez_send`) so the submission carries a valid signature for your key.

### Minimum Client Checklist

Your client must be able to:

1. Load or generate an IPv8 key pair
2. Join the Lab 1 community using the community ID above
3. Discover the server peer through IPv8 peer discovery
4. Compute a valid PoW over `(email, github_url, nonce)`
5. Send the submission message with your email, github URL, and nonce
6. Receive and display the server response

### Common Failure Cases

- Encoding the nonce in the wrong byte order
- Hashing the text form of the nonce instead of its 8-byte binary form
- Forgetting the `\n` separators in the hash input
- Accidentally including a trailing newline or whitespace in your URL string
- Using a non-TU-Delft email domain
- Changing your URL without re-mining a nonce for the new URL
- Forgetting to register a handler for the response message
- Accepting any peer in the community as the server instead of filtering by the server's public key
- Accidentally using a different private key than the one you intend to keep for later labs

## Deliverable

A working IPv8 client that:

1. Connects to the server's community
2. Computes and submits a valid PoW with your email and github URL
3. Receives and displays the server's response

You are done when you receive `Accepted`, `Accepted (already registered)`, `Accepted (github URL updated)`, or `Accepted (re-registered with new key)`.

There is nothing to submit manually. The repository URL you submitted is the canonical location of your client code; your public key is your proof of completion.