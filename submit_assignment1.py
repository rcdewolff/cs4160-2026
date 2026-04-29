import asyncio
import hashlib
import json
import struct
import time

from ipv8.community import Community
from ipv8.configuration import get_default_configuration
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import dataclass
from ipv8_service import IPv8

EMAIL = "r.c.dewolff@student.tudelft.nl"
GITHUB_URL = "https://github.com/rcdewolff/cs4160-2026/"

COMMUNITY_ID_HEX = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
SERVER_PUBKEY_HEX = (
	"4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb"
	"178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136"
	"c501ce5c09364e0ebb"
)

DIFFICULTY_LEADING_ZERO_BITS = 28
KEY_FILE = "my_ipv8_key.pem"
POW_FILE = "pow_result.json"


@dataclass(msg_id=1)
class SubmissionPayload:
	format_list = ["varlenHutf8", "varlenHutf8", "q"]
	email: str
	github_url: str
	nonce: int


@dataclass(msg_id=2)
class ResponsePayload:
	format_list = ["?", "varlenHutf8"]
	success: bool
	message: str


class PowCommunity(Community):
	community_id = bytes.fromhex(COMMUNITY_ID_HEX)

	def __init__(self, *args, **kwargs) -> None:
		super().__init__(*args, **kwargs)
		self._response_future: asyncio.Future[ResponsePayload] = (
			asyncio.get_event_loop().create_future()
		)
		self.add_message_handler(ResponsePayload, self.on_response)

	def find_server_peer(self):
		for peer in self.get_peers():
			if peer.public_key.key_to_bin().hex() == SERVER_PUBKEY_HEX:
				return peer
		return None

	async def submit(self, email: str, github_url: str, nonce: int) -> ResponsePayload:
		server = self.find_server_peer()
		if server is None:
			raise RuntimeError("Server peer not found yet")
		self.ez_send(server, SubmissionPayload(email, github_url, nonce))
		return await asyncio.wait_for(self._response_future, timeout=30)

	@lazy_wrapper(ResponsePayload)
	def on_response(self, peer, payload: ResponsePayload) -> None:
		if peer.public_key.key_to_bin().hex() != SERVER_PUBKEY_HEX:
			return
		if not self._response_future.done():
			self._response_future.set_result(payload)


def leading_zero_bits(digest: bytes) -> int:
	count = 0
	for byte in digest:
		if byte == 0:
			count += 8
			continue
		# Count leading zeros in this byte
		for bit in range(7, -1, -1):
			if byte & (1 << bit):
				return count
			count += 1
		return count
	return count


def compute_digest(email: str, github_url: str, nonce: int) -> bytes:
	prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
	return hashlib.sha256(prefix + struct.pack(">Q", nonce)).digest()


def load_pow_file(path: str) -> dict:
	with open(path, "r", encoding="utf-8") as handle:
		return json.load(handle)


def validate_pow_record(record: dict, difficulty_bits: int) -> None:
	try:
		email = record["email"]
		github_url = record["github_url"]
		nonce = int(record["nonce"])
		expected_hex = record["digest_hex"]
	except (KeyError, TypeError, ValueError) as exc:
		raise RuntimeError("Invalid PoW record format") from exc

	if nonce < 0 or nonce > 0x7FFF_FFFF_FFFF_FFFF:
		raise RuntimeError("Nonce out of 63-bit signed range")

	digest = compute_digest(email, github_url, nonce)
	if digest.hex() != expected_hex:
		raise RuntimeError("Digest mismatch for stored PoW record")
	if leading_zero_bits(digest) < difficulty_bits:
		raise RuntimeError("Digest does not meet difficulty")


async def wait_for_server_peer(community: PowCommunity, timeout: float = 30) -> None:
	start = time.time()
	while time.time() - start < timeout:
		if community.find_server_peer() is not None:
			return
		await asyncio.sleep(1)
	raise RuntimeError("Server peer not discovered in time")


async def main() -> None:
	config = get_default_configuration()
	config["keys"] = [
		{
			"alias": "my peer",
			"generation": "curve25519",
			"file": KEY_FILE,
		}
	]
	config["overlays"] = [
		{
			"class": "PowCommunity",
			"key": "my peer",
			"walkers": [
				{
					"type": "RandomWalk",
					"timeout": 3.0,
					"interval": 1.0,
				}
			],
			"initialize": {},
			"on_start": [],
		}
	]

	ipv8 = IPv8(config, extra_community_classes={"PowCommunity": PowCommunity})
	await ipv8.start()

	try:
		community = ipv8.get_overlay(PowCommunity)
		await wait_for_server_peer(community)

		record = load_pow_file(POW_FILE)
		validate_pow_record(record, DIFFICULTY_LEADING_ZERO_BITS)
		email = record["email"]
		github_url = record["github_url"]
		nonce = int(record["nonce"])

		response = await community.submit(email, github_url, nonce)
		print(f"Server response: success={response.success}, message={response.message}")
	finally:
		await ipv8.stop()


if __name__ == "__main__":
	asyncio.run(main())
