import asyncio
import json
from dataclasses import dataclass
from mine_pow import leading_zero_bits, compute_digest

from ipv8.peer import Peer
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs, get_default_configuration
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8_service import IPv8
from ipv8.util import run_forever

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


@dataclass
class SubmissionPayload(DataClassPayload[1]):
	email: str
	github_url: str
	nonce: int


@dataclass
class ResponsePayload(DataClassPayload[2]):
	success: bool
	message: str


class PowCommunity(Community):
	community_id = bytes.fromhex(COMMUNITY_ID_HEX)

	def __init__(self, settings) -> None:
		super().__init__(settings)
		self.add_message_handler(ResponsePayload, self.on_response)
		self.add_message_handler(SubmissionPayload, self.on_submission)
		ResponsePayload(False, "") # Weird fix on my end that somehow fixed handling the server response by initializing ResponsePayload once
		self.found_server_peer = False

	@lazy_wrapper(ResponsePayload)
	def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
		if peer.public_key.key_to_bin().hex() != SERVER_PUBKEY_HEX:
			return
		print(f"Received response from server: success={payload.success}, message={payload.message}")
		with open("submission_response.txt", "w", encoding="utf-8") as handle:
			handle.write(
				f"Received response from server: success={payload.success}, message={payload.message}\n"
			)
	
	@lazy_wrapper(SubmissionPayload)
	def on_submission(self, peer: Peer, payload: SubmissionPayload) -> None:
		print(f"Received submission from peer {peer}, ignoring since we are not the server")
		
	def started(self) -> None:
		print("Community started, looking for server peer...")
		async def find_server_peer() -> None:
			if not self.found_server_peer:
				for peer in self.get_peers():
					if peer.public_key.key_to_bin().hex() == SERVER_PUBKEY_HEX:
						print("Found server peer in community")
						self.found_server_peer = True
						self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, self.nonce))
						print("Submitted PoW result to server peer, waiting for response...")
						return
				print("Server peer not found yet, waiting for next peer update")
			else:
				self.cancel_all_pending_tasks()
		self.register_task("find_server_peer", find_server_peer, interval=5.0, delay=0)

		
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


async def main() -> None:
	print("Loading PoW record...")
	record = load_pow_file(POW_FILE)
	validate_pow_record(record, DIFFICULTY_LEADING_ZERO_BITS)
	print("PoW record is valid")
	PowCommunity.nonce = record["nonce"]

	builder = ConfigBuilder().clear_keys().clear_overlays()
	builder.add_key("my peer", "medium", KEY_FILE)
	builder.add_overlay("PowCommunity", "my peer",
											[WalkerDefinition(Strategy.RandomWalk,
																				10, {"timeout": 3.0})],
											default_bootstrap_defs, {}, [("started",)])
	await IPv8(builder.finalize(),
							extra_communities={"PowCommunity": PowCommunity}).start()
	await run_forever()


if __name__ == "__main__":
	asyncio.run(main())
