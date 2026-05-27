import argparse
import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8_service import IPv8


DEFAULT_COMMUNITY_ID_HEX = "4c61623247726f75705369676e696e6732303236"
DEFAULT_SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3d"
    "db6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b"
    "8401f5f683031e60c96"
)

GROUP_SIZE = 3
ROUND_COUNT = 3
REQUEST_RETRY_SECONDS = 0.5
REGISTER_RETRY_SECONDS = 1.0
RELAY_RETRY_SECONDS = 0.25
SIGNATURE_RETRY_SECONDS = 0.25
BUNDLE_RETRY_SECONDS = 0.75


# Message IDs 1-6 are the server protocol from assignment2.md.
@vp_compile
class RegisterPayload(VariablePayload):
    msg_id = 1

    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


@vp_compile
class RegistrationResponsePayload(VariablePayload):
    msg_id = 2

    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


@vp_compile
class ChallengeRequestPayload(VariablePayload):
    msg_id = 3

    format_list = ["varlenHutf8"]
    names = ["group_id"]


@vp_compile
class ChallengeResponsePayload(VariablePayload):
    msg_id = 4

    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


@vp_compile
class SignatureBundlePayload(VariablePayload):
    msg_id = 5

    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


@vp_compile
class RoundResultPayload(VariablePayload):
    msg_id = 6

    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


# Message IDs 7-9 are group-internal helper messages. They still use IPv8
# authenticated sends, so the peer public key is checked separately in handlers.
@vp_compile
class TeamNoncePayload(VariablePayload):
    msg_id = 7

    format_list = ["varlenHutf8", "q", "varlenH", "d", "q"]
    names = ["group_id", "round_number", "nonce", "deadline", "submitter_index"]


@vp_compile
class TeamSignaturePayload(VariablePayload):
    msg_id = 8

    format_list = ["varlenHutf8", "q", "varlenH", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce_hash", "signer_index", "signature"]


@vp_compile
class TeamAckPayload(VariablePayload):
    msg_id = 9

    format_list = ["varlenHutf8", "q", "varlenH", "varlenHutf8", "q"]
    names = ["group_id", "round_number", "nonce_hash", "ack_kind", "signer_index"]


@dataclass
class Lab2Config:
    member_keys: list[bytes]
    group_id: Optional[str]
    should_register: bool
    server_public_key: bytes
    community_id: bytes


@dataclass
class RoundState:
    # Per-round mutable state. This is reset whenever a new nonce is installed.
    round_number: int = 0
    nonce: Optional[bytes] = None
    deadline: float = 0.0
    nonce_source_is_server: bool = False
    signatures: dict[int, bytes] = field(default_factory=dict)
    signature_acks: set[int] = field(default_factory=set)
    outgoing_signature: Optional[TeamSignaturePayload] = None
    submitted_round: int = 0
    result_received_round: int = 0
    last_nonce_relay_at: float = 0.0
    last_signature_sent_at: float = 0.0
    last_bundle_sent_at: float = 0.0


class Lab2Community(Community):
    community_id = bytes.fromhex(DEFAULT_COMMUNITY_ID_HEX)
    config: Lab2Config

    def __init__(self, settings):
        super().__init__(settings)

        self.member_keys = self.config.member_keys
        self.member_key_hexes = [key.hex() for key in self.member_keys]
        self.member_public_keys = [default_eccrypto.key_from_public_bin(key) for key in self.member_keys]
        self.member_key_set = set(self.member_key_hexes)
        self.group_id = self.config.group_id
        self.should_register = self.config.should_register
        self.server_public_key = self.config.server_public_key
        self.server_public_key_hex = self.server_public_key.hex()

        # The local IPv8 key must be one of the registered group members.
        self.my_public_key = self.my_peer.public_key.key_to_bin()
        self.my_public_key_hex = self.my_public_key.hex()
        if self.my_public_key_hex not in self.member_key_set:
            raise RuntimeError("Local key is not one of the three member keys.")
        self.local_member_index = self.member_key_hexes.index(self.my_public_key_hex)

        self.server_peer: Optional[Peer] = None
        self.member_peers: dict[int, Peer] = {}
        self.logged_member_indices: set[int] = set()
        self.logged_server = False

        self.registration_done = False
        self.last_register_sent_at = 0.0
        self.waiting_challenge_round: Optional[int] = None
        self.last_challenge_request_at = 0.0
        self.rounds_completed = 0
        self.finished = False
        self.round_state = RoundState()

        # Server handlers and teammate handlers share the same Lab 2 community.
        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(TeamNoncePayload, self.on_team_nonce)
        self.add_message_handler(TeamSignaturePayload, self.on_team_signature)
        self.add_message_handler(TeamAckPayload, self.on_team_ack)

    def started(self):
        print("Joining Lab 2 community.")
        print("Local public key:", self.my_public_key_hex)
        print("Local member:", self.local_member_index + 1)
        self.register_task("tick", self.tick, interval=0.1, delay=0)

    async def tick(self):
        if self.finished:
            return

        # UDP messages can be lost, so the periodic tick handles discovery and
        # retries instead of relying on a single send per protocol step.
        now = time.time()
        self.discover_known_peers()
        self.retry_registration(now)
        self.maybe_start_round_one(now)
        self.retry_challenge_request(now)
        self.retry_nonce_relay(now)
        self.retry_signature(now)
        self.retry_bundle(now)

    def discover_known_peers(self):
        for peer in self.get_peers():
            peer_key_hex = peer.public_key.key_to_bin().hex()
            # Only this exact server key is trusted for server responses.
            if peer_key_hex == self.server_public_key_hex:
                self.server_peer = peer
                if not self.logged_server:
                    print("Verified server found:", peer.address)
                    self.logged_server = True
                continue

            member_index = self.member_index_for_key_hex(peer_key_hex)
            if member_index is None or member_index == self.local_member_index:
                continue

            # Teammates are recognized by the canonical registration keys.
            self.member_peers[member_index] = peer
            if member_index not in self.logged_member_indices:
                print(f"Teammate member {member_index + 1} found:", peer.address)
                self.logged_member_indices.add(member_index)

    def retry_registration(self, now: float):
        if not self.should_register or self.registration_done or not self.server_peer:
            return
        if now - self.last_register_sent_at < REGISTER_RETRY_SECONDS:
            return

        self.ez_send(
            self.server_peer,
            RegisterPayload(self.member_keys[0], self.member_keys[1], self.member_keys[2]),
        )
        self.last_register_sent_at = now
        print("Sent group registration request.")

    def maybe_start_round_one(self, now: float):
        # Member 1 starts the 10-second budget by requesting the first nonce.
        if self.group_id is None or self.rounds_completed > 0 or self.round_state.round_number != 0:
            return
        if self.local_member_index != 0 or not self.server_peer or not self.all_teammates_found():
            return
        if self.waiting_challenge_round is None:
            self.waiting_challenge_round = 1
            self.send_challenge_request(1, now)

    def retry_challenge_request(self, now: float):
        # Re-requesting during a live server round returns the same nonce, so
        # this retry is safe while waiting for a challenge response.
        if self.group_id is None or self.server_peer is None or self.waiting_challenge_round is None:
            return
        if self.round_state.round_number == self.waiting_challenge_round and self.round_state.nonce is not None:
            return
        if now - self.last_challenge_request_at < REQUEST_RETRY_SECONDS:
            return
        self.send_challenge_request(self.waiting_challenge_round, now)

    def send_challenge_request(self, round_number: int, now: Optional[float] = None):
        if self.group_id is None or self.server_peer is None:
            return
        self.ez_send(self.server_peer, ChallengeRequestPayload(self.group_id))
        self.last_challenge_request_at = time.time() if now is None else now
        print(f"Requested challenge for round {round_number}.")

    def retry_nonce_relay(self, now: float):
        state = self.round_state
        # Only the peer that received the nonce directly from the server relays
        # it repeatedly to the teammates.
        if not state.nonce or not state.nonce_source_is_server:
            return
        if state.round_number <= self.rounds_completed or state.result_received_round == state.round_number:
            return
        if now - state.last_nonce_relay_at < RELAY_RETRY_SECONDS:
            return
        self.broadcast_current_nonce(now)

    def retry_signature(self, now: float):
        state = self.round_state
        # Non-submitters keep sending their signature until the submitter ACKs it.
        if state.outgoing_signature is None:
            return
        if state.round_number <= self.rounds_completed or state.result_received_round == state.round_number:
            return
        if self.local_member_index in state.signature_acks:
            return
        if now - state.last_signature_sent_at < SIGNATURE_RETRY_SECONDS:
            return

        submitter_index = self.submitter_index_for_round(state.round_number)
        submitter_peer = self.member_peers.get(submitter_index)
        if submitter_peer is None:
            return

        self.ez_send(submitter_peer, state.outgoing_signature)
        state.last_signature_sent_at = now
        print(f"Sent signature for round {state.round_number} to member {submitter_index + 1}.")

    def retry_bundle(self, now: float):
        state = self.round_state
        # The current round submitter resends the complete bundle until a server
        # result arrives. The server makes duplicate accepted bundles harmless.
        if state.nonce is None or state.round_number <= self.rounds_completed:
            return
        if state.result_received_round == state.round_number:
            return
        if self.local_member_index != self.submitter_index_for_round(state.round_number):
            return
        if len(state.signatures) != GROUP_SIZE:
            return
        if state.submitted_round == state.round_number and now - state.last_bundle_sent_at < BUNDLE_RETRY_SECONDS:
            return

        self.submit_current_bundle(now)

    def install_nonce(self, round_number: int, nonce: bytes, deadline: float, source_is_server: bool):
        # A nonce defines the active round. All signatures must be over these
        # exact 32 raw bytes and ordered by the member list at submission time.
        if round_number < 1 or round_number > ROUND_COUNT:
            print("Ignored nonce for invalid round:", round_number)
            return
        if len(nonce) != 32:
            print("Ignored nonce with invalid length:", len(nonce))
            return
        if round_number <= self.rounds_completed:
            return

        state = self.round_state
        is_new_nonce = state.round_number != round_number or state.nonce != nonce
        if is_new_nonce:
            self.round_state = RoundState(
                round_number=round_number,
                nonce=nonce,
                deadline=deadline,
                nonce_source_is_server=source_is_server,
            )
            state = self.round_state
            print(
                f"Round {round_number} nonce installed. "
                f"Submitter: member {self.submitter_index_for_round(round_number) + 1}."
            )
        else:
            state.deadline = deadline
            state.nonce_source_is_server = state.nonce_source_is_server or source_is_server

        if self.waiting_challenge_round == round_number:
            self.waiting_challenge_round = None

        # Everyone signs immediately; only the round submitter keeps all three.
        self.add_own_signature()
        if source_is_server:
            self.broadcast_current_nonce(time.time())
        self.prepare_or_send_signature(time.time())
        self.retry_bundle(time.time())

    def add_own_signature(self):
        state = self.round_state
        if state.nonce is None or self.local_member_index in state.signatures:
            return

        signature = self.crypto.create_signature(self.my_peer.key, state.nonce)
        state.signatures[self.local_member_index] = signature
        print(f"Added own signature for round {state.round_number}.")

    def prepare_or_send_signature(self, now: float):
        state = self.round_state
        if state.nonce is None:
            return

        submitter_index = self.submitter_index_for_round(state.round_number)
        if self.local_member_index == submitter_index:
            return

        # The nonce hash prevents an old signature from being accepted for the
        # wrong challenge if messages arrive late.
        signature = state.signatures.get(self.local_member_index)
        if signature is None:
            return

        state.outgoing_signature = TeamSignaturePayload(
            self.group_id or "",
            state.round_number,
            self.nonce_hash(state.nonce),
            self.local_member_index,
            signature,
        )
        state.last_signature_sent_at = 0.0
        self.retry_signature(now)

    def broadcast_current_nonce(self, now: float):
        state = self.round_state
        if self.group_id is None or state.nonce is None:
            return

        submitter_index = self.submitter_index_for_round(state.round_number)
        payload = TeamNoncePayload(
            self.group_id,
            state.round_number,
            state.nonce,
            state.deadline,
            submitter_index,
        )
        for member_index, peer in self.member_peers.items():
            if member_index != self.local_member_index:
                self.ez_send(peer, payload)

        state.last_nonce_relay_at = now
        print(f"Relayed nonce for round {state.round_number}.")

    def submit_current_bundle(self, now: float):
        state = self.round_state
        if self.group_id is None or self.server_peer is None or state.nonce is None:
            return

        # Signature order must match the canonical registration order exactly.
        signatures = [state.signatures[index] for index in range(GROUP_SIZE)]
        self.ez_send(
            self.server_peer,
            SignatureBundlePayload(
                self.group_id,
                state.round_number,
                signatures[0],
                signatures[1],
                signatures[2],
            ),
        )
        state.submitted_round = state.round_number
        state.last_bundle_sent_at = now
        print(f"Submitted bundle for round {state.round_number}.")

    def all_teammates_found(self) -> bool:
        return len(self.member_peers) == GROUP_SIZE - 1

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin().hex() == self.server_public_key_hex

    def member_index_for_key_hex(self, key_hex: str) -> Optional[int]:
        try:
            return self.member_key_hexes.index(key_hex)
        except ValueError:
            return None

    def submitter_index_for_round(self, round_number: int) -> int:
        # Round-robin submitter order: member 1, then 2, then 3.
        return (round_number - 1) % GROUP_SIZE

    @staticmethod
    def nonce_hash(nonce: bytes) -> bytes:
        return hashlib.sha256(nonce).digest()

    def valid_group(self, group_id: str) -> bool:
        return self.group_id is not None and group_id == self.group_id

    def send_signature_ack(self, peer: Peer, round_number: int, nonce_hash: bytes, signer_index: int):
        if self.group_id is None:
            return
        self.ez_send(
            peer,
            TeamAckPayload(self.group_id, round_number, nonce_hash, "signature", signer_index),
        )

    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload):
        if not self.is_server(peer):
            print("Ignored registration response from non-server peer.")
            return

        self.registration_done = True
        print("Registration response received.")
        print("Success:", payload.success)
        print("Group ID:", payload.group_id)
        print("Message:", payload.message)

        if payload.success:
            self.group_id = payload.group_id
            self.config.group_id = payload.group_id

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload):
        if not self.is_server(peer):
            print("Ignored challenge response from non-server peer.")
            return

        print(
            f"Challenge response: round={payload.round_number}, "
            f"deadline={payload.deadline:.3f}."
        )
        self.install_nonce(payload.round_number, payload.nonce, payload.deadline, True)

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload: RoundResultPayload):
        if not self.is_server(peer):
            print("Ignored round result from non-server peer.")
            return

        print(
            "Round result: "
            f"success={payload.success}, round={payload.round_number}, "
            f"completed={payload.rounds_completed}, message={payload.message}"
        )

        if payload.success:
            # The successful submitter immediately asks for the next nonce.
            self.round_state.result_received_round = payload.round_number
            self.rounds_completed = max(self.rounds_completed, payload.rounds_completed)
            if payload.rounds_completed >= ROUND_COUNT:
                self.finished = True
                print("All 3 rounds completed.")
                return

            next_round = payload.round_number + 1
            if self.local_member_index == self.submitter_index_for_round(payload.round_number):
                self.waiting_challenge_round = next_round
                self.send_challenge_request(next_round)
            return

        lower_message = payload.message.lower()
        # Terminal failures need a fresh group or corrected configuration.
        if "budget exceeded" in lower_message or "group not found" in lower_message:
            self.round_state.result_received_round = payload.round_number
            self.finished = True
            print("Stopping because the server reported a terminal failure.")
        elif "not a member" in lower_message or "already completed" in lower_message:
            self.round_state.result_received_round = payload.round_number
            self.finished = True
            print("Stopping because the server rejected the group or submitter state.")
        elif "invalid signature" in lower_message:
            self.round_state.submitted_round = 0
            print("Server rejected a signature. Waiting for corrected signatures if any arrive.")
        elif "wrong round number" in lower_message:
            self.round_state.result_received_round = payload.round_number
            self.finished = True
            print("Stopping because local round state is out of sync with the server.")
        elif "submitter already used" in lower_message:
            self.round_state.result_received_round = payload.round_number
            self.finished = True
            print("Stopping because submitter order no longer matches the server.")
        elif "no active challenge" in lower_message and payload.round_number < ROUND_COUNT:
            print("No active challenge reported; requesting the next round in case the success reply was lost.")
            self.waiting_challenge_round = payload.round_number + 1
            self.send_challenge_request(payload.round_number + 1)
        else:
            print("Non-terminal rejection received; retries remain active where possible.")

    @lazy_wrapper(TeamNoncePayload)
    def on_team_nonce(self, peer: Peer, payload: TeamNoncePayload):
        print(f"Team nonce received!!! Round: {payload.round_number}")
        sender_index = self.member_index_for_key_hex(peer.public_key.key_to_bin().hex())
        if sender_index is None:
            return
        print("here")
        if not self.valid_group(payload.group_id):
            return
        print("here2")
        if payload.submitter_index != self.submitter_index_for_round(payload.round_number):
            return

        print(f"Nonce relay received for round {payload.round_number} from member {sender_index + 1}.")
        self.install_nonce(payload.round_number, payload.nonce, payload.deadline, False)

    @lazy_wrapper(TeamSignaturePayload)
    def on_team_signature(self, peer: Peer, payload: TeamSignaturePayload):
        sender_index = self.member_index_for_key_hex(peer.public_key.key_to_bin().hex())
        if sender_index is None:
            return
        if not self.valid_group(payload.group_id):
            return
        if sender_index != payload.signer_index:
            return
        if payload.round_number != self.round_state.round_number:
            return
        if self.round_state.nonce is None:
            return
        if payload.nonce_hash != self.nonce_hash(self.round_state.nonce):
            return
        if self.local_member_index != self.submitter_index_for_round(payload.round_number):
            return

        # Verify locally before spending time submitting a bundle the server
        # would reject.
        signer_public_key = self.member_public_keys[payload.signer_index]
        if not self.crypto.is_valid_signature(signer_public_key, self.round_state.nonce, payload.signature):
            print(f"Ignored invalid signature from member {payload.signer_index + 1}.")
            return

        self.round_state.signatures[payload.signer_index] = payload.signature
        self.send_signature_ack(peer, payload.round_number, payload.nonce_hash, payload.signer_index)
        print(
            f"Accepted signature from member {payload.signer_index + 1} "
            f"for round {payload.round_number} ({len(self.round_state.signatures)}/3)."
        )
        self.retry_bundle(time.time())

    @lazy_wrapper(TeamAckPayload)
    def on_team_ack(self, peer: Peer, payload: TeamAckPayload):
        sender_index = self.member_index_for_key_hex(peer.public_key.key_to_bin().hex())
        if sender_index is None:
            return
        if not self.valid_group(payload.group_id) or payload.ack_kind != "signature":
            return
        if payload.round_number != self.round_state.round_number:
            return
        if self.round_state.nonce is None or payload.nonce_hash != self.nonce_hash(self.round_state.nonce):
            return
        if payload.signer_index != self.local_member_index:
            return
        if sender_index != self.submitter_index_for_round(payload.round_number):
            return

        self.round_state.signature_acks.add(payload.signer_index)
        print(f"Signature ACK received for round {payload.round_number}.")


def parse_public_key_hex(value: str, label: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be valid hex.") from exc
    if len(key) != 74:
        raise argparse.ArgumentTypeError(f"{label} must be 74 bytes / 148 hex characters.")
    return key


def parse_args():
    parser = argparse.ArgumentParser(description="Lab 2 coordinated group signing client.")
    parser.add_argument("--key-file", required=True, help="Lab 1 private key file. Do not commit it.")
    parser.add_argument("--member1-key", required=True, help="Member 1 public key hex.")
    parser.add_argument("--member2-key", required=True, help="Member 2 public key hex.")
    parser.add_argument("--member3-key", required=True, help="Member 3 public key hex.")
    parser.add_argument("--group-id", help="Registered Lab 2 group id.")
    parser.add_argument("--register", action="store_true", help="Register the ordered member keys.")
    parser.add_argument(
        "--community-id",
        default=DEFAULT_COMMUNITY_ID_HEX,
        help="Lab 2 community id hex.",
    )
    parser.add_argument(
        "--server-public-key",
        default=DEFAULT_SERVER_PUBLIC_KEY_HEX,
        help="Lab 2 server public key hex.",
    )
    return parser.parse_args()


def build_config(args) -> Lab2Config:
    # These three keys define both the group registration and signature order.
    member_keys = [
        parse_public_key_hex(args.member1_key, "--member1-key"),
        parse_public_key_hex(args.member2_key, "--member2-key"),
        parse_public_key_hex(args.member3_key, "--member3-key"),
    ]
    if len(set(member_keys)) != GROUP_SIZE:
        raise ValueError("Member public keys must be unique.")

    try:
        community_id = bytes.fromhex(args.community_id)
    except ValueError as exc:
        raise ValueError("--community-id must be valid hex.") from exc
    if len(community_id) != 20:
        raise ValueError("--community-id must be 20 bytes / 40 hex characters.")

    server_public_key = parse_public_key_hex(args.server_public_key, "--server-public-key")

    if not args.register and not args.group_id:
        raise ValueError("Provide --group-id for a run, or use --register to register the group.")

    return Lab2Config(
        member_keys=member_keys,
        group_id=args.group_id,
        should_register=args.register,
        server_public_key=server_public_key,
        community_id=community_id,
    )


async def main():
    args = parse_args()
    config = build_config(args)

    Lab2Community.community_id = config.community_id
    Lab2Community.config = config

    # Reuse the same curve25519 key file that passed Lab 1.
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("lab-key", "curve25519", args.key_file)
    builder.add_overlay(
        "Lab2Community",
        "lab-key",
        [
            WalkerDefinition(
                Strategy.RandomWalk,
                20,
                {"timeout": 3.0},
            )
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "Lab2Community": Lab2Community,
        },
    )

    await ipv8.start()
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())