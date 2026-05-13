import asyncio
from dataclasses import dataclass
from typing import Dict, Optional, Set

from ipv8.peer import Peer
from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8_service import IPv8
from ipv8.util import run_forever


COMMUNITY_ID_HEX = "4c61623247726f75705369676e696e6732303236"
SERVER_PUBKEY_HEX = (
	"4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3d"
	"db6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b"
	"8401f5f683031e60c96"
)

GROUP_ID = "YOUR_GROUP_ID"
KEY_FILE = "my_ipv8_key.pem"

MEMBER_PUBKEYS_HEX = [
	"",
	"",
	"",
]

@dataclass
class ChallengeRequestPayload(DataClassPayload[3]):
	group_id: str


@dataclass
class ChallengeResponsePayload(DataClassPayload[4]):
	nonce: bytes
	round_number: int
	deadline: float


@dataclass
class SignatureBundlePayload(DataClassPayload[5]):
	group_id: str
	round_number: int
	sig1: bytes
	sig2: bytes
	sig3: bytes


@dataclass
class RoundResultPayload(DataClassPayload[6]):
	success: bool
	round_number: int
	rounds_completed: int
	message: str


@dataclass
class ReadyPayload(DataClassPayload[10]):
	member_pubkey: bytes


@dataclass
class NoncePayload(DataClassPayload[11]):
	round_number: int
	nonce: bytes
	deadline: float


@dataclass
class SignatureSharePayload(DataClassPayload[12]):
	round_number: int
	signer_pubkey: bytes
	signature: bytes


class GroupSigningCommunity(Community):
	community_id = bytes.fromhex(COMMUNITY_ID_HEX)

	def __init__(self, settings) -> None:
		super().__init__(settings)
		self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
		self.add_message_handler(RoundResultPayload, self.on_round_result)
		self.add_message_handler(ReadyPayload, self.on_ready)
		self.add_message_handler(NoncePayload, self.on_nonce)
		self.add_message_handler(SignatureSharePayload, self.on_signature_share)

		self.member_pubkeys_hex = [pk.lower() for pk in MEMBER_PUBKEYS_HEX]
		self.member_pubkeys_set = set(self.member_pubkeys_hex)
		self.my_pubkey_hex = self.my_peer.public_key.key_to_bin().hex()
		self.disabled = self.my_pubkey_hex not in self.member_pubkeys_set
		if self.disabled:
			print("Local key not in MEMBER_PUBKEYS_HEX. Fix config.")

		self.server_peer: Optional[Peer] = None
		self.member_peers: Dict[str, Peer] = {}
		self.ready_members: Set[str] = set()

		self.current_round = 0
		self.current_nonce: Optional[bytes] = None
		self.round_sigs: Dict[str, bytes] = {}
		self.rounds_completed = 0
		self.submitted_round = 0
		self.sent_signature_round = 0
		self.requested_round1 = False

	def started(self) -> None:
		print("Community started")
		self.register_task("tick", self.tick, interval=0.5, delay=0)

	async def tick(self) -> None:
		if self.disabled:
			return

		for peer in self.get_peers():
			pubkey_hex = peer.public_key.key_to_bin().hex()
			if pubkey_hex == SERVER_PUBKEY_HEX:
				self.server_peer = peer
			elif pubkey_hex in self.member_pubkeys_set and pubkey_hex != self.my_pubkey_hex:
				self.member_peers[pubkey_hex] = peer

		if self.server_peer and len(self.member_peers) == 2:
			if len(self.ready_members) < 3:
				payload = ReadyPayload(self.my_peer.public_key.key_to_bin())
				for peer in self.member_peers.values():
					self.ez_send(peer, payload)
				self.ready_members.add(self.my_pubkey_hex)

			if len(self.ready_members) == 3 and self.current_round == 0 and not self.requested_round1:
				if self.my_pubkey_hex == self.member_pubkeys_hex[0]:
					self.ez_send(self.server_peer, ChallengeRequestPayload(GROUP_ID))
					self.requested_round1 = True
					print("Requested challenge for round 1")

	def handle_nonce(self, round_number: int, nonce: bytes) -> None:
		if round_number <= self.rounds_completed:
			return
		if self.current_round != round_number or self.current_nonce != nonce:
			self.current_round = round_number
			self.current_nonce = nonce
			self.round_sigs = {}
			self.submitted_round = 0
			self.sent_signature_round = 0

		submitter_hex = self.member_pubkeys_hex[round_number - 1]
		if self.my_pubkey_hex == submitter_hex:
			signature = self.crypto.create_signature(self.my_peer.key, nonce)
			self.round_sigs[self.my_pubkey_hex] = signature
			return

		if self.sent_signature_round == round_number:
			return
		peer = self.member_peers.get(submitter_hex)
		if not peer:
			return
		signature = self.crypto.create_signature(self.my_peer.key, nonce)
		payload = SignatureSharePayload(
			round_number, self.my_peer.public_key.key_to_bin(), signature
		)
		self.ez_send(peer, payload)
		self.sent_signature_round = round_number
		print(f"Sent signature for round {round_number}")

	def submit_if_ready(self) -> None:
		if not self.server_peer:
			return
		if self.submitted_round == self.current_round:
			return
		if len(self.round_sigs) < 3:
			return
		ordered = [self.round_sigs[self.member_pubkeys_hex[i]] for i in range(3)]
		payload = SignatureBundlePayload(
			GROUP_ID, self.current_round, ordered[0], ordered[1], ordered[2]
		)
		self.ez_send(self.server_peer, payload)
		self.submitted_round = self.current_round
		print(f"Submitted bundle for round {self.current_round}")

	@lazy_wrapper(ReadyPayload)
	def on_ready(self, peer: Peer, payload: ReadyPayload) -> None:
		pubkey_hex = peer.public_key.key_to_bin().hex()
		if pubkey_hex not in self.member_pubkeys_set:
			return
		if payload.member_pubkey != peer.public_key.key_to_bin():
			return
		self.ready_members.add(pubkey_hex)
		print(f"Ready from member {pubkey_hex}")

	@lazy_wrapper(ChallengeResponsePayload)
	def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
		if peer.public_key.key_to_bin().hex() != SERVER_PUBKEY_HEX:
			return
		self.handle_nonce(payload.round_number, payload.nonce)
		relay = NoncePayload(payload.round_number, payload.nonce, payload.deadline)
		for member_peer in self.member_peers.values():
			self.ez_send(member_peer, relay)
		print(f"Nonce received for round {payload.round_number}")

	@lazy_wrapper(NoncePayload)
	def on_nonce(self, peer: Peer, payload: NoncePayload) -> None:
		if peer.public_key.key_to_bin().hex() not in self.member_pubkeys_set:
			return
		self.handle_nonce(payload.round_number, payload.nonce)
		print(f"Nonce relayed for round {payload.round_number}")

	@lazy_wrapper(SignatureSharePayload)
	def on_signature_share(self, peer: Peer, payload: SignatureSharePayload) -> None:
		pubkey_hex = peer.public_key.key_to_bin().hex()
		if pubkey_hex not in self.member_pubkeys_set:
			return
		if payload.signer_pubkey.hex() != pubkey_hex:
			return
		if self.current_round != payload.round_number:
			return
		submitter_hex = self.member_pubkeys_hex[payload.round_number - 1]
		if self.my_pubkey_hex != submitter_hex:
			return
		self.round_sigs[pubkey_hex] = payload.signature
		self.submit_if_ready()
		print(f"Received signature from {pubkey_hex} for round {payload.round_number}")

	@lazy_wrapper(RoundResultPayload)
	def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
		if peer.public_key.key_to_bin().hex() != SERVER_PUBKEY_HEX:
			return
		print(
			"Round result: "
			f"success={payload.success}, round={payload.round_number}, "
			f"completed={payload.rounds_completed}, message={payload.message}"
		)
		if payload.success:
			self.rounds_completed = max(self.rounds_completed, payload.rounds_completed)
			if payload.rounds_completed >= 3:
				print("All rounds completed")
				return
		next_round = payload.round_number + 1
		if payload.success and next_round <= 3:
			requester_hex = self.member_pubkeys_hex[next_round - 2]
			if self.my_pubkey_hex == requester_hex:
				self.ez_send(peer, ChallengeRequestPayload(GROUP_ID))
				print(f"Requested challenge for round {next_round}")


async def main() -> None:
	if not GROUP_ID or GROUP_ID == "YOUR_GROUP_ID":
		raise RuntimeError("Set GROUP_ID to your registered group id")
	if len(MEMBER_PUBKEYS_HEX) != 3:
		raise RuntimeError("MEMBER_PUBKEYS_HEX must have exactly 3 entries")
	lowered = [pk.lower() for pk in MEMBER_PUBKEYS_HEX]
	if len(set(lowered)) != 3:
		raise RuntimeError("MEMBER_PUBKEYS_HEX contains duplicates")
	for pk in lowered:
		if not pk:
			raise RuntimeError("MEMBER_PUBKEYS_HEX contains empty entries")
		try:
			bytes.fromhex(pk)
		except ValueError as exc:
			raise RuntimeError("MEMBER_PUBKEYS_HEX has invalid hex") from exc
	builder = ConfigBuilder().clear_keys().clear_overlays()
	builder.add_key("my peer", "medium", KEY_FILE)
	builder.add_overlay(
		"GroupSigningCommunity",
		"my peer",
		[WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
		default_bootstrap_defs,
		{},
		[("started",)],
	)
	await IPv8(
		builder.finalize(), extra_communities={"GroupSigningCommunity": GroupSigningCommunity}
	).start()
	await run_forever()


if __name__ == "__main__":
	asyncio.run(main())
