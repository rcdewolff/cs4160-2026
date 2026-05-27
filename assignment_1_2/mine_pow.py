import hashlib
import json
import struct
import time

EMAIL = "r.c.dewolff@student.tudelft.nl"
GITHUB_URL = "https://github.com/rcdewolff/cs4160-2026/"

DIFFICULTY_LEADING_ZERO_BITS = 28
POW_FILE = "pow_result.json"


def leading_zero_bits(digest: bytes) -> int:
	count = 0
	for byte in digest:
		if byte == 0:
			count += 8
			continue
		for bit in range(7, -1, -1):
			if byte & (1 << bit):
				return count
			count += 1
		return count
	return count


def compute_digest(email: str, github_url: str, nonce: int) -> bytes:
	prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
	return hashlib.sha256(prefix + struct.pack(">Q", nonce)).digest()


def mine_nonce(email: str, github_url: str, difficulty_bits: int) -> int:
	start = time.time()
	nonce = 0
	while True:
		if nonce > 0x7FFF_FFFF_FFFF_FFFF:
			raise RuntimeError("Nonce overflow")
		digest = compute_digest(email, github_url, nonce)
		if leading_zero_bits(digest) >= difficulty_bits:
			return nonce
		if nonce % 1_000_000 == 0 and nonce != 0:
			elapsed = time.time() - start
			rate = nonce / max(elapsed, 1e-6)
			print(f"Tried {nonce:,} nonces @ {rate:,.0f}/s")
		nonce += 1


def write_pow_file(path: str, email: str, github_url: str, nonce: int, digest: bytes) -> None:
	record = {
		"email": email,
		"github_url": github_url,
		"nonce": nonce,
		"digest_hex": digest.hex(),
		"difficulty_bits": DIFFICULTY_LEADING_ZERO_BITS,
	}
	with open(path, "w", encoding="utf-8") as handle:
		json.dump(record, handle, indent=2)


def main() -> None:
	print("Mining PoW...")
	nonce = mine_nonce(EMAIL, GITHUB_URL, DIFFICULTY_LEADING_ZERO_BITS)
	digest = compute_digest(EMAIL, GITHUB_URL, nonce)
	write_pow_file(POW_FILE, EMAIL, GITHUB_URL, nonce, digest)
	print(f"Found nonce: {nonce}")
	print(f"Wrote {POW_FILE}")


if __name__ == "__main__":
	main()
