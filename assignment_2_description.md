# Lab 2: Coordinated Group Signing over IPv8

## Overview

You and two teammates build IPv8 clients that sign challenges from a server within a strict shared budget.

Each round, the server issues a 32-byte nonce. All 3 members sign it; one collects the 3 signatures and submits the bundle. Across 3 rounds, each must be submitted by a different member. **All 3 rounds must finish inside 10 seconds wall-clock**, measured from the moment the server sends the round-1 nonce. Faster groups earn bonus credit — the lab is graded on speed, not just correctness.

## Server

| Parameter | Value |
|---|---|
| Community ID | `4c61623247726f75705369676e696e6732303236` (20 bytes / 40 hex) |
| Server public key | `4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96` (74 bytes / 148 hex) |
| Group size | 3 |
| Rounds | 3 (different submitter each round) |
| Total budget | **10 seconds wall-clock for all 3 rounds combined**, starting when the server sends the round-1 nonce |
| Deadline | `2026-05-19T23:59:59 UTC` |

Reach the server via IPv8 peer discovery on the community ID above. Filter peers by the published public key — never trust a peer whose key does not match.

## Prerequisites and deliverable

- Use the **same Ed25519 key pair** each member used in Lab 1. The server checks every member's key against Lab 1's records and rejects any key not found there.
- Add your Lab 2 client code to the **same personal GitHub repository** each member registered in Lab 1. Each member commits to their own repo.
- If a teammate lost their Lab 1 key, they recover it in Lab 1 first (`email + new key`), then your trio registers a fresh Lab 2 group with the new key. Old groups stay on the records and are harmless.

## Wire-level authentication

Send every message — to the server and to teammates — with IPv8's authenticated send (`ez_send` and friends). Each packet carries a `BinMemberAuthenticationPayload` with your public key and a signature over the payload. The server reads your key from this header to identify you.

Unsigned packets are dropped silently. If you get no reply at all, check this first.

## Part 1: Group registration

### Register (message_id = 1)

Any member sends:

| Field | Type | Wire | Description |
|---|---|---|---|
| `member1_key` | bytes | `varlenH` | Ed25519 public key of member 1 |
| `member2_key` | bytes | `varlenH` | Ed25519 public key of member 2 |
| `member3_key` | bytes | `varlenH` | Ed25519 public key of member 3 |

The order you list the keys here is the **canonical signature order** for every later bundle.

### Response (message_id = 2)

| Field | Type | Wire |
|---|---|---|
| `success` | bool | `?` |
| `group_id` | str | `varlenHutf8` |
| `message` | str | `varlenHutf8` |

| Response | Meaning |
|---|---|
| `success=True, "Group registered"` | New group, fresh `group_id` returned |
| `success=True, "Group already registered"` | A group with this exact 3-member set already exists; the same `group_id` is returned (UDP-retry safe) |
| `success=False, "Rejected: sender must be a group member"` | Sender's key is not one of the 3 listed keys |
| `success=False, "Rejected: duplicate public keys"` | Two or 3 of the listed keys are equal |
| `success=False, "Rejected: public keys not in Lab 1 records: <hex>[, <hex>]"` | One or more keys never passed Lab 1; the server lists the offending keys verbatim |

A pubkey may belong to multiple groups (recovery path). The server does not block re-registration if a member is already in another group.

## Part 2: Challenge rounds

Your group must complete **3 rounds, each submitted by a different member**. The server identifies the submitter by the IPv8 peer key on the bundle's auth header.

### Challenge request (message_id = 3)

| Field | Type | Wire |
|---|---|---|
| `group_id` | str | `varlenHutf8` |

### Challenge response (message_id = 4)

The server replies with a nonce. **The 10-second wall-clock timer starts when the round-1 response is sent** and runs until the round-3 bundle is accepted. The same deadline applies to all 3 rounds.

| Field | Type | Wire | Description |
|---|---|---|---|
| `nonce` | bytes | `varlenH` | 32 random bytes |
| `round_number` | int | `q` | 1, 2, or 3 |
| `deadline` | float | `d` | Unix timestamp — the same value for every challenge in this group |

Re-requesting during a live round returns the same nonce, round, and deadline; it does not extend the budget.

### Bundle submission (message_id = 5)

| Field | Type | Wire |
|---|---|---|
| `group_id` | str | `varlenHutf8` |
| `round_number` | int | `q` |
| `sig1` | bytes | `varlenH` |
| `sig2` | bytes | `varlenH` |
| `sig3` | bytes | `varlenH` |

Each `sigN` is an Ed25519 signature over the **raw 32-byte nonce** by `memberN`'s private key. Order must match the registration order.

### Round result (message_id = 6)

| Field | Type | Wire |
|---|---|---|
| `success` | bool | `?` |
| `round_number` | int | `q` |
| `rounds_completed` | int | `q` |
| `message` | str | `varlenHutf8` |

A `RoundResultPayload` (message_id = 6) is the server's reply to **both** a `SignatureBundle` (success / verdict) **and** an early-rejection of a `ChallengeRequest` that the server cannot fulfil. Cases:

| Response | Triggered by | Meaning |
|---|---|---|
| `success=True, "Round N recorded at T.TTs of 10s (M/3)"` | Bundle | Accepted. `T.TT` is wall-clock seconds since the round-1 challenge — your running total against the 10-second budget. |
| `success=True, "Round 3 recorded at T.TTs of 10s — all 3 rounds done"` | Bundle | All rounds in. `T.TT` is your **combined elapsed** — the bonus signal. Lower is better. |
| `success=False, "Rejected: budget exceeded (T.TTs elapsed)"` | Bundle | The 10-second window closed before the bundle arrived. The group must re-register to retry. |
| `success=False, "Rejected: invalid signature from member N"` | Bundle | Signature N did not verify against member N's registered key. The active challenge stays live; fix and resubmit before the budget closes. |
| `success=False, "Rejected: submitter already used in a previous round"` | Bundle | A different teammate must submit. |
| `success=False, "Rejected: wrong round number"` | Bundle | `round_number` does not match the current active round. |
| `success=False, "Rejected: submitter is not a member of this group"` | Bundle | Submitter's IPv8 key is not one of the 3 registered keys. |
| `success=False, "Rejected: no active challenge for this group"` | Bundle | No live challenge: the budget already closed, or this bundle duplicates a successful submission. |
| `success=False, "Rejected: group not found"` | Challenge request | `group_id` does not match any registered group. |
| `success=False, "Rejected: requester is not a member of this group"` | Challenge request | The peer asking for a challenge is not one of the 3 registered members. (Parallel wording to the bundle-path "submitter is not a member..." rejection.) |
| `success=False, "Rejected: group already completed all rounds"` | Challenge request | The group is already at `rounds_completed=3`. No more challenges will be issued. |

## Coordination

The server sees `ChallengeRequest` going in and `SignatureBundle` coming out. Everything between is your design.

Your teammates appear as peers in the same Lab 2 community. Filter by their public keys to recognise them; route group-internal messages within it.

For example:

- **Coordinator.** One member relays the nonce, collects signatures, submits.
- **Broadcast.** Everyone sends to everyone; whoever has all 3 signatures first submits.
- **Round-robin.** Pre-assign a different submitter per round; each runs their own round.

## Grading

The server records every accepted round and its timing. Grading happens after the deadline, using that data.

- **Baseline.** 3 accepted rounds, 3 different submitters, all inside the 10-second window, on or before `2026-05-19T23:59:59 UTC`. Each member earns credit individually.
- **System Design.** The 10-second window leaves room for choices: how many messages, who relays what, what happens on packet loss. 
- **Bonus** Faster, simpler, more robust designs score higher than ones that scrape by.

## Common pitfalls

- Sending a registration request from a peer that is not one of the 3 listed members.
- Using a key that did not pass Lab 1 (the server names the offending key in hex).
- Reordering signatures relative to registration order.
- Reusing the same submitter across rounds.
- Burning the 10-second window before round 3 lands.
- Hammering challenge requests during a live round expecting a fresh budget — the server returns the same challenge until the budget closes.
- Forgetting to register handlers for response messages.
- Accepting any peer in the community as the server instead of filtering by public key.