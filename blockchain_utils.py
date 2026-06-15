from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Iterable

HASH_SIZE = 32
HEADER_SIZE = 84


def _ensure_hash(value: bytes, label: str) -> bytes:
	if len(value) != HASH_SIZE:
		raise ValueError(f"{label} must be {HASH_SIZE} bytes.")
	return value


def _ensure_uint64(value: int, label: str) -> int:
	if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
		raise ValueError(f"{label} must fit in uint64.")
	return value


def _ensure_uint32(value: int, label: str) -> int:
	if value < 0 or value > 0xFFFFFFFF:
		raise ValueError(f"{label} must fit in uint32.")
	return value


def pack_block_header(
	prev_hash: bytes,
	txs_hash: bytes,
	timestamp: int,
	difficulty: int,
	nonce: int,
) -> bytes:
	_ensure_hash(prev_hash, "prev_hash")
	_ensure_hash(txs_hash, "txs_hash")
	_ensure_uint64(timestamp, "timestamp")
	_ensure_uint32(difficulty, "difficulty")
	_ensure_uint64(nonce, "nonce")
	# Big-endian wire format per spec.
	return struct.pack(">32s32sQIQ", prev_hash, txs_hash, timestamp, difficulty, nonce
	)


def hash_bytes(data: bytes) -> bytes:
	return hashlib.sha256(data).digest()


def hash_block_header(header_bytes: bytes) -> bytes:
	if len(header_bytes) != HEADER_SIZE:
		raise ValueError(f"header_bytes must be {HEADER_SIZE} bytes.")
	return hash_bytes(header_bytes)


def block_hash(
	prev_hash: bytes,
	txs_hash: bytes,
	timestamp: int,
	difficulty: int,
	nonce: int,
) -> bytes:
	header = pack_block_header(prev_hash, txs_hash, timestamp, difficulty, nonce)
	return hash_block_header(header)


def tx_hash(sender_key: bytes, data: bytes, timestamp: int, signature: bytes) -> bytes:
	_ensure_uint64(timestamp, "timestamp")
	timestamp_be: bytes = timestamp.to_bytes(8, "big", signed=False)
	return hash_bytes(b"".join([sender_key, data, timestamp_be, signature]))


def txs_hash(tx_hashes: Iterable[bytes]) -> bytes:
	parts = []
	for txh in tx_hashes:
		parts.append(_ensure_hash(txh, "tx_hash"))
	return hash_bytes(b"".join(parts))


def split_tx_hashes(blob: bytes) -> list[bytes]:
	if len(blob) % HASH_SIZE != 0:
		raise ValueError("tx_hashes blob length must be a multiple of 32.")
	return [blob[i : i + HASH_SIZE] for i in range(0, len(blob), HASH_SIZE)]


def leading_zero_bits(digest: bytes) -> int:
	count = 0
	for value in digest:
		if value == 0:
			count += 8
			continue
		count += 8 - value.bit_length()
		break
	return count


def has_valid_pow(digest: bytes, difficulty: int) -> bool:
	if difficulty < 0:
		raise ValueError("difficulty must be non-negative.")
	return leading_zero_bits(digest) >= difficulty


def mine_nonce(
	prev_hash: bytes,
	txs_hash_value: bytes,
	timestamp: int,
	difficulty: int,
	start_nonce: int = 0,
	max_attempts: int = 0,
) -> tuple[int, bytes]:
	_ensure_hash(prev_hash, "prev_hash")
	_ensure_hash(txs_hash_value, "txs_hash")
	_ensure_uint64(start_nonce, "start_nonce")
	if max_attempts < 0:
		raise ValueError("max_attempts must be non-negative.")

	attempts = 0
	nonce = start_nonce
	while max_attempts == 0 or attempts < max_attempts:
		digest = block_hash(prev_hash, txs_hash_value, timestamp, difficulty, nonce)
		if has_valid_pow(digest, difficulty):
			return nonce, digest
		nonce = (nonce + 1) & 0xFFFFFFFFFFFFFFFF
		attempts += 1

	raise RuntimeError("PoW not found within max_attempts.")


@dataclass(frozen=True)
class BlockHeader:
	prev_hash: bytes
	txs_hash: bytes
	timestamp: int
	difficulty: int
	nonce: int

	def pack(self) -> bytes:
		return pack_block_header(
			self.prev_hash,
			self.txs_hash,
			self.timestamp,
			self.difficulty,
			self.nonce,
		)

	def hash(self) -> bytes:
		return hash_block_header(self.pack())


@dataclass
class Block:
	header: BlockHeader
	tx_hashes: list[bytes] = field(default_factory=list)

	def txs_hash(self) -> bytes:
		return txs_hash(self.tx_hashes)

	def is_body_hash_valid(self) -> bool:
		return self.txs_hash() == self.header.txs_hash
