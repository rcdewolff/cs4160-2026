from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Optional

from ipv8.community import Community, CommunitySettings
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from blockchain_utils import (
	Block,
	BlockHeader,
	HASH_SIZE,
	block_hash,
	has_valid_pow,
	split_tx_hashes,
	tx_hash,
	txs_hash,
)


DEFAULT_SERVER_PUBLIC_KEY_HEX = (
	"4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4"
	"350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f"
	"791324495e083331ce6"
)
PUBLIC_KEY = os.environ.get("PUB_KEY", None)
PUBLIC_KEY_MEMBER1 = os.environ.get("PUB_KEY_MEMBER1", None)
PUBLIC_KEY_MEMBER2 = os.environ.get("PUB_KEY_MEMBER2", None)

ALLOWED_KEY_HEXES = [PUBLIC_KEY, PUBLIC_KEY_MEMBER1, PUBLIC_KEY_MEMBER2, DEFAULT_SERVER_PUBLIC_KEY_HEX]


# Blockchain community payloads.
@vp_compile
class SubmitTransactionPayload(VariablePayload):
	msg_id = 1

	format_list = ["varlenH", "varlenH", "q", "varlenH"]
	names = ["sender_key", "data", "timestamp", "signature"]


@vp_compile
class SubmitTransactionResponsePayload(VariablePayload):
	msg_id = 2

	format_list = ["?", "varlenH", "varlenHutf8"]
	names = ["success", "tx_hash", "message"]


@vp_compile
class GetChainHeightPayload(VariablePayload):
	msg_id = 3

	format_list = ["q"]
	names = ["request_id"]


@vp_compile
class ChainHeightResponsePayload(VariablePayload):
	msg_id = 4

	format_list = ["q", "q", "varlenH"]
	names = ["request_id", "height", "tip_hash"]


@vp_compile
class GetBlockPayload(VariablePayload):
	msg_id = 5

	format_list = ["q"]
	names = ["height"]


@vp_compile
class BlockResponsePayload(VariablePayload):
	msg_id = 6

	format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
	names = [
		"height",
		"prev_hash",
		"txs_hash",
		"timestamp",
		"difficulty",
		"nonce",
		"block_hash",
		"tx_hashes",
	]


ASSIGNMENT_MESSAGE_PAYLOADS = (
	SubmitTransactionPayload,
	SubmitTransactionResponsePayload,
	GetChainHeightPayload,
	ChainHeightResponsePayload,
	GetBlockPayload,
	BlockResponsePayload,
)


class BlockChainCommunitySettings(CommunitySettings):
	allowed_key_hexes: set[str]
	member_key_hexes: list[str]
	difficulty: int
	enable_mining: bool
	mine_batch_size: int
	sync_interval: float
	max_sync_blocks: int


@dataclass(frozen=True)
class TransactionRecord:
	sender_key: bytes
	data: bytes
	timestamp: int
	signature: bytes
	hash: bytes


@dataclass(frozen=True)
class ReceivedBlock:
	height: int
	block: Block


@dataclass
class PeerSyncState:
	target_height: int
	mode: str = "forward"
	next_height: int = 0
	common_height: Optional[int] = None
	candidate_blocks: dict[int, ReceivedBlock] = None

	def __post_init__(self):
		if self.candidate_blocks is None:
			self.candidate_blocks = {}


class BlockchainCommunity(Community):
	community_id = bytes(20)
	settings_class = BlockChainCommunitySettings

	def __init__(self, settings):
		super().__init__(settings)

		self.crypto = default_eccrypto
		self.allowed_key_hexes = {
			key.lower()
			for key in getattr(settings, "allowed_key_hexes", set()) or ALLOWED_KEY_HEXES
			if key
		}

		self.member_key_hexes = [
			key.lower()
			for key in getattr(settings, "member_key_hexes", []) or sorted(self.allowed_key_hexes)
			if key
		]
		
		self.difficulty = getattr(settings, "difficulty", 0)
		self.enable_mining = getattr(settings, "enable_mining", False)
		self.mine_batch_size = getattr(settings, "mine_batch_size", 1000)
		self.sync_interval = getattr(settings, "sync_interval", 1.0)
		self.max_sync_blocks = getattr(settings, "max_sync_blocks", 64)

		self.mempool: list[bytes] = []
		self.mempool_set: set[bytes] = set()
		self.transactions: dict[bytes, TransactionRecord] = {}
		self.chain: list[Block] = []
		self.block_heights_by_hash: dict[bytes, int] = {}
		self.peer_heights: dict[str, tuple[int, bytes]] = {}
		self.peer_sync: dict[str, PeerSyncState] = {}
		self.last_tx_response: Optional[SubmitTransactionResponsePayload] = None
		self.next_request_id = 1
		self.mining_generation = 0
		self._init_genesis()

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)

	def started(self):
		self.register_task("sync_loop", self.sync_loop, interval=self.sync_interval, delay=self.sync_interval)
		if self.enable_mining:
			self.register_task("background_miner", self.mine_forever, interval=None, delay=0)

	def _is_approved_peer(self, peer: Peer) -> bool:
		if not self.allowed_key_hexes:
			return True
		return peer.public_key.key_to_bin().hex().lower() in self.allowed_key_hexes

	def _is_teammate_peer(self, peer: Peer) -> bool:
		peer_key = peer.public_key.key_to_bin().hex().lower()
		my_key = self.my_peer.public_key.key_to_bin().hex().lower()
		if peer_key == my_key:
			return False
		if self.member_key_hexes:
			return peer_key in self.member_key_hexes
		return self._is_approved_peer(peer)

	def _is_my_turn_to_mine(self, height: int) -> bool:
		if not self.member_key_hexes:
			return True
		my_key = self.my_peer.public_key.key_to_bin().hex().lower()
		expected_key = self.member_key_hexes[(height - 1) % len(self.member_key_hexes)]
		return my_key == expected_key

	def _init_genesis(self):
		genesis_header = BlockHeader(
			prev_hash=b"\x00" * HASH_SIZE,
			txs_hash=txs_hash([]),
			timestamp=0,
			difficulty=0,
			nonce=0,
		)
		self.chain.append(Block(header=genesis_header, tx_hashes=[]))
		self._rebuild_block_index()

	def _rebuild_block_index(self):
		self.block_heights_by_hash = {
			block.header.hash(): height for height, block in enumerate(self.chain)
		}

	def height(self) -> int:
		return len(self.chain) - 1

	def tip_hash(self) -> bytes:
		return self.chain[-1].header.hash()

	def _next_request_id(self) -> int:
		request_id = self.next_request_id
		self.next_request_id += 1
		return request_id

	def _add_transaction_record(self, record: TransactionRecord) -> bool:
		self.transactions[record.hash] = record
		if record.hash in self.mempool_set:
			return False
		self.mempool.append(record.hash)
		self.mempool_set.add(record.hash)
		return True

	def _validate_transaction_payload(self, payload) -> tuple[bool, bytes, str]:
		try:
			timestamp_bytes = payload.timestamp.to_bytes(8, "big", signed=False)
		except OverflowError:
			return False, b"", "bad timestamp"
		message = payload.sender_key + payload.data + timestamp_bytes
		try:
			signer_key = self.crypto.key_from_public_bin(payload.sender_key)
		except Exception:
			return False, b"", "bad sender key"

		if not self.crypto.is_valid_signature(signer_key, message, payload.signature):
			return False, b"", "invalid signature"

		return True, tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature), "accepted"

	def _record_from_payload(self, payload, tx_digest: bytes) -> TransactionRecord:
		return TransactionRecord(
			payload.sender_key,
			payload.data,
			payload.timestamp,
			payload.signature,
			tx_digest,
		)

	def _remove_mined_transactions(self, tx_hashes: list[bytes]):
		for txh in tx_hashes:
			self.mempool_set.discard(txh)
			try:
				self.mempool.remove(txh)
			except ValueError:
				pass

	def _payload_for_block(self, height: int, block: Block) -> BlockResponsePayload:
		return BlockResponsePayload(
			height,
			block.header.prev_hash,
			block.header.txs_hash,
			block.header.timestamp,
			block.header.difficulty,
			block.header.nonce,
			block.header.hash(),
			b"".join(block.tx_hashes),
		)

	def _block_from_payload(self, payload: BlockResponsePayload) -> Optional[ReceivedBlock]:
		if payload.height < 0:
			return None
		if len(payload.prev_hash) != HASH_SIZE or len(payload.txs_hash) != HASH_SIZE:
			return None
		if len(payload.block_hash) != HASH_SIZE:
			return None
		try:
			body_hashes = split_tx_hashes(payload.tx_hashes)
		except ValueError:
			return None

		expected_header_hash = block_hash(
			payload.prev_hash,
			payload.txs_hash,
			payload.timestamp,
			payload.difficulty,
			payload.nonce,
		)
		if expected_header_hash != payload.block_hash:
			return None
		if not has_valid_pow(expected_header_hash, payload.difficulty):
			return None
		if txs_hash(body_hashes) != payload.txs_hash:
			return None

		header = BlockHeader(
			prev_hash=payload.prev_hash,
			txs_hash=payload.txs_hash,
			timestamp=payload.timestamp,
			difficulty=payload.difficulty,
			nonce=payload.nonce,
		)
		return ReceivedBlock(payload.height, Block(header=header, tx_hashes=body_hashes))

	def _accept_new_tip_block(self, received: ReceivedBlock, relay: bool = True) -> bool:
		if received.height != len(self.chain):
			return False
		if received.block.header.prev_hash != self.tip_hash():
			return False
		self.chain.append(received.block)
		self.block_heights_by_hash[received.block.header.hash()] = received.height
		self._remove_mined_transactions(received.block.tx_hashes)
		self.interrupt_mining()
		if relay:
			self.broadcast_block(received.height, received.block)
		return True

	def _replace_chain_from(self, start_height: int, blocks: list[Block]) -> bool:
		if start_height <= 0 or start_height > len(self.chain):
			return False
		if start_height + len(blocks) <= len(self.chain):
			return False

		parent_hash = self.chain[start_height - 1].header.hash()
		for block in blocks:
			if block.header.prev_hash != parent_hash:
				return False
			parent_hash = block.header.hash()

		self.chain = self.chain[:start_height] + blocks
		self._rebuild_block_index()
		for block in blocks:
			self._remove_mined_transactions(block.tx_hashes)
		self.interrupt_mining()
		return True

	def interrupt_mining(self):
		self.mining_generation += 1

	def broadcast_block(self, height: int, block: Block):
		payload = self._payload_for_block(height, block)
		for peer in self.get_peers():
			if self._is_teammate_peer(peer):
				self.ez_send(peer, payload)

	def broadcast_transaction(self, record: TransactionRecord):
		payload = SubmitTransactionPayload(
			record.sender_key,
			record.data,
			record.timestamp,
			record.signature,
		)
		for peer in self.get_peers():
			if self._is_teammate_peer(peer):
				self.ez_send(peer, payload)

	async def sync_loop(self):
		for peer in self.get_peers():
			if self._is_teammate_peer(peer):
				self.ez_send(peer, GetChainHeightPayload(self._next_request_id()))

	async def mine_forever(self):
		while True:
			mined = await self.mine_next_block()
			if mined is None:
				await asyncio.sleep(0.1)

	async def mine_next_block(self) -> Optional[Block]:
		next_height = len(self.chain)
		if not self._is_my_turn_to_mine(next_height):
			return None

		generation = self.mining_generation
		prev_hash = self.tip_hash()
		tx_hashes = list(self.mempool)
		txs_hash_value = txs_hash(tx_hashes)
		timestamp = int(time.time())
		nonce = 0
		while generation == self.mining_generation:
			for _ in range(self.mine_batch_size):
				digest = block_hash(prev_hash, txs_hash_value, timestamp, self.difficulty, nonce)
				if has_valid_pow(digest, self.difficulty):
					block = Block(
						BlockHeader(prev_hash, txs_hash_value, timestamp, self.difficulty, nonce),
						tx_hashes,
					)
					if self._accept_new_tip_block(ReceivedBlock(next_height, block), relay=False):
						self.broadcast_block(next_height, block)
						return block
					return None
				nonce = (nonce + 1) & 0xFFFFFFFFFFFFFFFF
			await asyncio.sleep(0)
		return None

	def mine_next_block_sync(self, timestamp: int = 1) -> Optional[Block]:
		next_height = len(self.chain)
		if not self._is_my_turn_to_mine(next_height):
			return None
		prev_hash = self.tip_hash()
		tx_hashes = list(self.mempool)
		txs_hash_value = txs_hash(tx_hashes)
		nonce = 0
		while True:
			digest = block_hash(prev_hash, txs_hash_value, timestamp, self.difficulty, nonce)
			if has_valid_pow(digest, self.difficulty):
				block = Block(
					BlockHeader(prev_hash, txs_hash_value, timestamp, self.difficulty, nonce),
					tx_hashes,
				)
				if self._accept_new_tip_block(ReceivedBlock(next_height, block), relay=False):
					self.broadcast_block(next_height, block)
					return block
				return None
			nonce += 1

	def request_peer_block(self, peer: Peer, height: int):
		if self._is_teammate_peer(peer) and height >= 0:
			self.ez_send(peer, GetBlockPayload(height))

	def _start_forward_sync(self, peer: Peer, target_height: int):
		peer_key = peer.public_key.key_to_bin().hex().lower()
		next_height = min(len(self.chain), target_height)
		self.peer_sync[peer_key] = PeerSyncState(
			target_height=target_height,
			mode="forward",
			next_height=next_height,
		)
		self.request_peer_block(peer, next_height)

	def _start_find_common_sync(self, peer: Peer, target_height: int, first_block: Optional[ReceivedBlock] = None):
		peer_key = peer.public_key.key_to_bin().hex().lower()
		check_height = min(self.height(), target_height)
		state = PeerSyncState(
			target_height=target_height,
			mode="find_common",
			next_height=check_height,
		)
		if first_block is not None and first_block.height > self.height():
			state.candidate_blocks[first_block.height] = first_block
		self.peer_sync[peer_key] = state
		self.request_peer_block(peer, check_height)

	def _continue_suffix_fetch(self, peer: Peer, state: PeerSyncState):
		if state.common_height is None:
			return
		for next_height in range(state.common_height + 1, state.target_height + 1):
			if next_height not in state.candidate_blocks:
				if len(state.candidate_blocks) >= self.max_sync_blocks:
					return
				state.mode = "fetch_suffix"
				state.next_height = next_height
				self.request_peer_block(peer, next_height)
				return
		self._try_apply_sync_candidate(state)

	def _try_apply_sync_candidate(self, state: PeerSyncState):
		if state.common_height is None:
			return False
		expected_start = state.common_height + 1
		blocks = []
		for height in range(expected_start, state.target_height + 1):
			received = state.candidate_blocks.get(height)
			if received is None:
				return False
			blocks.append(received.block)
		return self._replace_chain_from(expected_start, blocks)

	def _handle_sync_block(self, peer: Peer, received: ReceivedBlock) -> bool:
		peer_key = peer.public_key.key_to_bin().hex().lower()
		state = self.peer_sync.get(peer_key)
		if state is None:
			return False

		if state.mode == "forward":
			if received.height != state.next_height:
				return False
			if received.height == len(self.chain) and received.block.header.prev_hash == self.tip_hash():
				self._accept_new_tip_block(received, relay=False)
				if received.height < state.target_height:
					state.next_height = received.height + 1
					self.request_peer_block(peer, state.next_height)
				else:
					self.peer_sync.pop(peer_key, None)
				return True
			self._start_find_common_sync(peer, state.target_height, received)
			return True

		if state.mode == "find_common":
			if received.height != state.next_height:
				return False
			if received.height < len(self.chain) and self.chain[received.height].header.hash() == received.block.header.hash():
				state.common_height = received.height
				self._continue_suffix_fetch(peer, state)
				return True
			if received.height <= 0:
				self.peer_sync.pop(peer_key, None)
				return False
			state.next_height = received.height - 1
			self.request_peer_block(peer, state.next_height)
			return True

		if state.mode == "fetch_suffix":
			if received.height != state.next_height:
				return False
			state.candidate_blocks[received.height] = received
			self._continue_suffix_fetch(peer, state)
			if self.height() >= state.target_height:
				self.peer_sync.pop(peer_key, None)
			return True

		return False

	@lazy_wrapper(SubmitTransactionPayload)
	def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload):
		if not self._is_approved_peer(peer):
			return

		success, tx_digest, message = self._validate_transaction_payload(payload)
		if success:
			record = self._record_from_payload(payload, tx_digest)
			is_new = self._add_transaction_record(record)
			if is_new:
				self.broadcast_transaction(record)
		self.ez_send(peer, SubmitTransactionResponsePayload(success, tx_digest, message))

	@lazy_wrapper(SubmitTransactionResponsePayload)
	def on_submit_transaction_response(
		self,
		peer: Peer,
		payload: SubmitTransactionResponsePayload,
	):
		if not self._is_approved_peer(peer):
			return
		self.last_tx_response = payload

	@lazy_wrapper(GetChainHeightPayload)
	def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload):
		if not self._is_approved_peer(peer):
			return

		self.ez_send(
			peer,
			ChainHeightResponsePayload(payload.request_id, self.height(), self.tip_hash()),
		)

	@lazy_wrapper(ChainHeightResponsePayload)
	def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponsePayload):
		if not self._is_approved_peer(peer):
			return
		if len(payload.tip_hash) != HASH_SIZE:
			return
		peer_key = peer.public_key.key_to_bin().hex().lower()
		self.peer_heights[peer_key] = (payload.height, payload.tip_hash)
		if payload.height > self.height():
			self._start_forward_sync(peer, payload.height)
		elif payload.height == self.height() and payload.tip_hash != self.tip_hash():
			self.peer_sync.pop(peer_key, None)

	@lazy_wrapper(GetBlockPayload)
	def on_get_block(self, peer: Peer, payload: GetBlockPayload):
		if not self._is_approved_peer(peer):
			return
		if payload.height < 0 or payload.height >= len(self.chain):
			return

		self.ez_send(peer, self._payload_for_block(payload.height, self.chain[payload.height]))

	@lazy_wrapper(BlockResponsePayload)
	def on_block_response(self, peer: Peer, payload: BlockResponsePayload):
		if not self._is_approved_peer(peer):
			return
		received = self._block_from_payload(payload)
		if received is None:
			return
		if self._handle_sync_block(peer, received):
			return
		if received.block.header.hash() in self.block_heights_by_hash:
			return

		if self._accept_new_tip_block(received):
			self.peer_sync.pop(peer.public_key.key_to_bin().hex().lower(), None)
			return
		if received.height > self.height():
			self._start_find_common_sync(peer, received.height, received)
