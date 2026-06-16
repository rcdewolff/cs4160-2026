import asyncio
import hashlib
import os
import random
import time
from collections import deque

from ipv8.community import Community, CommunitySettings
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from blockchain import Blockchain
from blockchain_utils import (
	Block,
	BlockHeader,
	HASH_SIZE,
	has_valid_pow,
	mine_nonce,
	split_tx_hashes,
	tx_hash,
	txs_hash,
)
from mempool import Mempool, Tx
from config import (
	DIFFICULTY,
	MINE_CHUNK,
	BLOCK_INTERVAL_RANGE,
	SYNC_INTERVAL,
	SYNC_DELAY,
	SYNC_DOWN_WINDOW,
	FETCH_BATCH,
	PENDING_CAP,
	PRUNE_INTERVAL,
)

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


@vp_compile
class TransactionGossipPayload(VariablePayload):
	msg_id = 7

	format_list = SubmitTransactionPayload.format_list
	names = SubmitTransactionPayload.names


@vp_compile
class CheckpointProposalPayload(VariablePayload):
	msg_id = 8

	format_list = ["q", "varlenH", "q", "varlenH"]
	names = ["height", "block_hash", "previous_height", "previous_hash"]


@vp_compile
class CheckpointAckPayload(VariablePayload):
	msg_id = 9

	format_list = ["q", "varlenH", "q", "varlenH", "varlenH", "varlenH"]
	names = ["height", "block_hash", "previous_height", "previous_hash", "signer_key", "signature"]


CHECKPOINT_DOMAIN = b"Lab3CheckpointV1"

class BlockChainCommunitySettings(CommunitySettings):
	allowed_key_hexes: set[str]
	data_dir: str


class BlockchainCommunity(Community):
	community_id = bytes(20)
	settings_class = BlockChainCommunitySettings

	def __init__(self, settings):
		super().__init__(settings)

		self.crypto = default_eccrypto
		self.allowed_key_hexes = set(getattr(settings, "allowed_key_hexes", set()))
		data_dir_base = getattr(settings, "data_dir", "chaindata")
		local_store_id = hashlib.sha256(self.my_peer.public_key.key_to_bin()).hexdigest()[:16]
		self._data_dir = os.path.join(
			data_dir_base,
			local_store_id,
		)
		# The grading server is an approved peer (it queries us) but not a chain peer: we never
		# poll it or push our tip to it, we only answer what it asks.
		self.server_key_hex = getattr(settings, "server_key_hex", "")

		# Block tree. self.chain is the canonical, height-indexed main chain; it is rebuilt by
		# _set_tip on every reorg. Never append to it directly outside _init_genesis/_set_tip.
		# self.blocks: dict[bytes, Block] = {}
		# self.height_by_hash: dict[bytes, int] = {}
		# self.best_tip: bytes = b""
		# self.chain: list[Block] = []
		self.pending_blocks: dict[bytes, Block] = {}  # orphans keyed by their own block hash

		# Transactions. known_txs is the never-pruned source of truth so a reorg that orphans the
		# test transaction puts it back in the mempool to be re-mined.
		# self.known_txs: set[bytes] = set()
		# self._tx_order: list[bytes] = []
		# self.mempool: list[bytes] = []
		# self.mempool_set: set[bytes] = set()

		# Peer sync state.
		self.peer_heights: dict[str, tuple[int, bytes]] = {}
		self._req_counter = 0
		self.last_tx_response = None
		self._prune_in_progress = False
		self._checkpoint_acks: dict[tuple[int, bytes, int, bytes], dict[str, str]] = {}
		self._checkpoint_votes_cast: dict[tuple[int, int], bytes] = {}
		self._checkpoint_vote_signatures: dict[tuple[int, bytes, int, bytes], bytes] = {}
		self._checkpoint_proposals_sent: set[tuple[int, bytes, int, bytes]] = set()
		self._checkpoint_apply_started: set[tuple[int, bytes, int, bytes]] = set()
		self._checkpoint_apply_tasks: dict[tuple[int, bytes, int, bytes], asyncio.Task] = {}

		self.mempool = Mempool()
		self.blockchain = Blockchain(self._init_genesis(), self.mempool, DIFFICULTY, data_dir=self._data_dir)
		# self.peer_heights = {}

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)
		self.add_message_handler(TransactionGossipPayload, self.on_transaction_gossip)
		self.add_message_handler(CheckpointProposalPayload, self.on_checkpoint_proposal)
		self.add_message_handler(CheckpointAckPayload, self.on_checkpoint_ack)

	def started(self) -> None:
		# Called once by IPv8 after the overlay loads (run_node passes the ("started",) hook).
		self.register_task("mine", self._mine_loop, ignore=(Exception,))
		self.register_task(
			"sync", self._sync_step, interval=SYNC_INTERVAL, delay=SYNC_DELAY, ignore=(Exception,)
		)
		self.register_task(
			"prune", self._prune_step, interval=PRUNE_INTERVAL, delay=PRUNE_INTERVAL, ignore=(Exception,)
		)

	async def unload(self) -> None:
		self.blockchain.store.close()
		await super().unload()

	def _is_approved_peer(self, peer: Peer) -> bool:
		return peer.public_key.key_to_bin().hex() in self.allowed_key_hexes

	def _teammate_peers(self) -> list[Peer]:
		# Approved peers we run consensus with: everyone allowed except the grading server.
		result = []
		for peer in self.get_peers():
			key_hex = peer.public_key.key_to_bin().hex()
			if key_hex in self.allowed_key_hexes and key_hex != self.server_key_hex:
				result.append(peer)
		return result

	def _checkpoint_member_key_hexes(self) -> set[str]:
		members = {key.lower() for key in self.allowed_key_hexes}
		if self.server_key_hex:
			members.discard(self.server_key_hex.lower())
		members.add(self.my_peer.public_key.key_to_bin().hex())
		return members

	def _checkpoint_quorum_size(self) -> int:
		member_count = len(self._checkpoint_member_key_hexes())
		return max(1, (2 * member_count + 2) // 3)

	def _is_checkpoint_peer(self, peer: Peer) -> bool:
		key_hex = peer.public_key.key_to_bin().hex()
		return key_hex in self._checkpoint_member_key_hexes()

	def _gossip_transaction(self, payload, exclude_peer: Peer) -> None:
		exclude_key = exclude_peer.public_key.key_to_bin().hex()
		gossip = TransactionGossipPayload(
			payload.sender_key,
			payload.data,
			payload.timestamp,
			payload.signature,
		)
		for peer in self.get_peers():
			if peer.public_key.key_to_bin().hex() == exclude_key:
				continue
			if self._is_approved_peer(peer):
				self.ez_send(peer, gossip)

	def _init_genesis(self) -> Block:
		genesis_header = BlockHeader(
			prev_hash=b"\x00" * HASH_SIZE,
			txs_hash=txs_hash([]),
			timestamp=0,
			difficulty=0,
			nonce=0,
		)
		return Block(header=genesis_header, tx_hashes=[])

	# --- Consensus core --------------------------------------------------------------------

	def _connect_orphans(self, root: bytes) -> list[bytes]:
		# Connect any buffered blocks whose parent just became available (transitively). Uses a
		# worklist, not recursion; pending_blocks only shrinks so this terminates.
		connected = [root]
		work = deque([root])
		while work:
			parent = work.popleft()
			for oh, orphan in list(self.pending_blocks.items()):
				if orphan.header.prev_hash != parent:
					continue
				self.pending_blocks.pop(oh, None)
				if oh in self.blockchain.blocks:
					continue
				self.blockchain.add_block(orphan)
				connected.append(oh)
				work.append(oh)
		return connected

	def add_block(self, block: Block) -> bool:
		"""Validate and integrate a block. Handles dedup, orphan buffering, fork choice and reorg.

		Synchronous on purpose: both the miner and the network path call it, and running it to
		completion between event-loop yields keeps the chain state consistent without locks.
		"""
		bh = block.header.hash()
		parent = block.header.prev_hash
		if parent not in self.blockchain.blocks:
			if len(self.pending_blocks) < PENDING_CAP:
				self.pending_blocks[bh] = block
			return False
		success = self.blockchain.add_block(block)
		if success:
			self._connect_orphans(bh)
		else:
			return False
		return True

	def _validate_transaction_payload(self, payload) -> tuple[bool, bytes, str]:
		if payload.timestamp < 0:
			return False, b"", "bad timestamp"

		message = (
			payload.sender_key
			+ payload.data
			+ payload.timestamp.to_bytes(8, "big", signed=False)
		)
		try:
			signer_key = self.crypto.key_from_public_bin(payload.sender_key)
		except Exception:
			return False, b"", "bad sender key"

		if not self.crypto.is_valid_signature(signer_key, message, payload.signature):
			return False, b"", "invalid signature"

		return True, tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature), "accepted"

	def _add_transaction_hash(self, tx: Tx) -> bool:
		txid, is_new = self.mempool.add(tx)
		return is_new

	# --- Quorum checkpoints ---------------------------------------------------------------

	def _checkpoint_key(
		self,
		height: int,
		block_hash: bytes,
		previous_height: int,
		previous_hash: bytes,
	) -> tuple[int, bytes, int, bytes]:
		return (height, block_hash, previous_height, previous_hash)

	def _checkpoint_vote_message(
		self,
		height: int,
		block_hash: bytes,
		previous_height: int,
		previous_hash: bytes,
	) -> bytes:
		return b"".join(
			[
				CHECKPOINT_DOMAIN,
				self.community_id,
				height.to_bytes(8, "big", signed=False),
				block_hash,
				previous_height.to_bytes(8, "big", signed=False),
				previous_hash,
			]
		)

	def _checkpoint_payload_is_valid(
		self,
		height: int,
		block_hash: bytes,
		previous_height: int,
		previous_hash: bytes,
	) -> bool:
		if height < 0 or previous_height < 0:
			return False
		if len(block_hash) != HASH_SIZE or len(previous_hash) != HASH_SIZE:
			return False
		return self.blockchain.can_finalize_checkpoint(height, block_hash, previous_height, previous_hash)

	def _make_checkpoint_ack(
		self,
		height: int,
		block_hash: bytes,
		previous_height: int,
		previous_hash: bytes,
	) -> CheckpointAckPayload | None:
		if not self._checkpoint_payload_is_valid(height, block_hash, previous_height, previous_hash):
			return None

		vote_round = (previous_height, height)
		previous_vote = self._checkpoint_votes_cast.get(vote_round)
		if previous_vote is not None and previous_vote != block_hash:
			return None
		self._checkpoint_votes_cast[vote_round] = block_hash

		key = self._checkpoint_key(height, block_hash, previous_height, previous_hash)
		signature = self._checkpoint_vote_signatures.get(key)
		if signature is None:
			message = self._checkpoint_vote_message(height, block_hash, previous_height, previous_hash)
			signature = self.crypto.create_signature(self.my_peer.key, message)
			self._checkpoint_vote_signatures[key] = signature

		return CheckpointAckPayload(
			height,
			block_hash,
			previous_height,
			previous_hash,
			self.my_peer.public_key.key_to_bin(),
			signature,
		)

	def _broadcast_checkpoint_proposal(self, payload: CheckpointProposalPayload) -> None:
		for peer in self._teammate_peers():
			self.ez_send(peer, payload)

	def _broadcast_checkpoint_ack(self, payload: CheckpointAckPayload) -> None:
		for peer in self._teammate_peers():
			self.ez_send(peer, payload)

	def _propose_checkpoint(self, plan) -> None:
		height = plan.floor
		block_hash = plan.checkpoint_hash
		previous_height = self.blockchain.checkpoint_height
		previous_hash = self.blockchain.checkpoint_hash
		if not self._checkpoint_payload_is_valid(height, block_hash, previous_height, previous_hash):
			return

		key = self._checkpoint_key(height, block_hash, previous_height, previous_hash)
		if key in self._checkpoint_proposals_sent:
			return
		self._checkpoint_proposals_sent.add(key)

		proposal = CheckpointProposalPayload(height, block_hash, previous_height, previous_hash)
		ack = self._make_checkpoint_ack(height, block_hash, previous_height, previous_hash)
		self._broadcast_checkpoint_proposal(proposal)
		if ack is not None:
			self._record_checkpoint_ack(ack)
			self._broadcast_checkpoint_ack(ack)

	def _record_checkpoint_ack(self, payload: CheckpointAckPayload) -> bool:
		if len(payload.signer_key) == 0 or len(payload.signature) == 0:
			return False
		if not self._checkpoint_payload_is_valid(
			payload.height,
			payload.block_hash,
			payload.previous_height,
			payload.previous_hash,
		):
			return False

		signer_hex = payload.signer_key.hex()
		if signer_hex not in self._checkpoint_member_key_hexes():
			return False

		try:
			signer_key = self.crypto.key_from_public_bin(payload.signer_key)
		except Exception:
			return False
		message = self._checkpoint_vote_message(
			payload.height,
			payload.block_hash,
			payload.previous_height,
			payload.previous_hash,
		)
		if not self.crypto.is_valid_signature(signer_key, message, payload.signature):
			return False

		key = self._checkpoint_key(
			payload.height,
			payload.block_hash,
			payload.previous_height,
			payload.previous_hash,
		)
		votes = self._checkpoint_acks.setdefault(key, {})
		votes.setdefault(signer_hex, payload.signature.hex())

		if len(votes) >= self._checkpoint_quorum_size():
			self._start_checkpoint_apply(key)
		return True

	def _start_checkpoint_apply(self, key: tuple[int, bytes, int, bytes]) -> None:
		if key in self._checkpoint_apply_started or self._prune_in_progress:
			return
		height, block_hash, _previous_height, _previous_hash = key
		plan = self.blockchain.make_prune_plan_for(height, block_hash)
		if plan is None:
			return

		votes = self._checkpoint_acks.get(key, {})
		signatures = tuple(f"{signer}:{signature}" for signer, signature in sorted(votes.items()))
		self._checkpoint_apply_started.add(key)
		self._prune_in_progress = True
		task = asyncio.create_task(self._apply_checkpoint_plan(key, plan, signatures))
		self._checkpoint_apply_tasks[key] = task

		def done_callback(done_task):
			self._checkpoint_apply_tasks.pop(key, None)
			try:
				done_task.result()
			except Exception:
				self._checkpoint_apply_started.discard(key)
				self._logger.exception("checkpoint prune failed")

		task.add_done_callback(done_callback)

	async def _apply_checkpoint_plan(
		self,
		key: tuple[int, bytes, int, bytes],
		plan,
		signatures: tuple[str, ...],
	) -> None:
		try:
			await asyncio.to_thread(self.blockchain.apply_prune_plan, plan, signatures)
			self.blockchain.finalize_prune_plan(plan)
			self._checkpoint_acks = {
				checkpoint_key: votes
				for checkpoint_key, votes in self._checkpoint_acks.items()
				if checkpoint_key[0] > self.blockchain.checkpoint_height
			}
		finally:
			self._prune_in_progress = False

	# --- Mining ----------------------------------------------------------------------------

	async def _mine_loop(self) -> None:
		while True:
			try:
				parent = self.blockchain.tip
				# parent = self.best_tip
				body = list(self.mempool.free_txs.keys())
				# body = list(self.mempool)
				commit = txs_hash(body)
				timestamp = int(time.time())
				difficulty = DIFFICULTY
				nonce = 0
				mined = None

				# Mine in chunks, yielding to the loop between them and aborting if a better tip
				# arrives (which also changes the mempool we should be mining).
				while self.blockchain.tip == parent:
					try:
						nonce, _digest = mine_nonce(
							parent, commit, timestamp, difficulty,
							start_nonce=nonce, max_attempts=MINE_CHUNK,
						)
						mined = nonce
						break
					except RuntimeError:
						nonce += MINE_CHUNK
						if nonce > 0xFFFFFFFFFFFFFFFF:
							nonce = 0
							timestamp = int(time.time())
						await asyncio.sleep(0)

				if mined is not None and self.blockchain.tip == parent:
					header = BlockHeader(
						prev_hash=parent,
						txs_hash=commit,
						timestamp=timestamp,
						difficulty=difficulty,
						nonce=mined,
					)
					if self.add_block(Block(header=header, tx_hashes=body)):
						self._announce_tip()
					await asyncio.sleep(random.uniform(*BLOCK_INTERVAL_RANGE))
				else:
					await asyncio.sleep(0)
			except asyncio.CancelledError:
				raise
			except Exception:
				self._logger.exception("mine loop iteration failed")
				await asyncio.sleep(0.5)

	# --- Pull-based sync (spec messages only) ---------------------------------------------

	async def _sync_step(self) -> None:
		# Safety-net poll: ask teammates for their height/tip. The reaction (fetching when a peer
		# is ahead) happens in on_chain_height_response, which also fires for mining pushes.
		for peer in self._teammate_peers():
			self._req_counter += 1
			self.ez_send(peer, GetChainHeightPayload(self._req_counter))

	def _announce_tip(self) -> None:
		# Push our new tip to teammates so they pull immediately instead of waiting for a poll.
		height = self.blockchain.chain_height
		for peer in self._teammate_peers():
			self.ez_send(peer, ChainHeightResponsePayload(0, height, self.blockchain.tip))

	def _fetch_from(self, peer: Peer, their_h: int) -> None:
		our_h = self.blockchain.chain_height
		start = max(0, our_h - SYNC_DOWN_WINDOW)
		end = min(their_h, our_h + FETCH_BATCH)
		for height in range(start, end + 1):
			self.ez_send(peer, GetBlockPayload(height))

	async def _prune_step(self) -> None:
		if self._prune_in_progress:
			return
		plan = self.blockchain.make_prune_plan()
		if plan is None:
			return

		self._propose_checkpoint(plan)

	# --- Message handlers ------------------------------------------------------------------

	@lazy_wrapper(SubmitTransactionPayload)
	def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload):
		if not self._is_approved_peer(peer):
			return

		success, tx_digest, message = self._validate_transaction_payload(payload)
		if not success:
			self.ez_send(peer, SubmitTransactionResponsePayload(False, tx_digest, message))
			return

		tx: Tx = (payload.sender_key, payload.data, payload.timestamp, payload.signature)

		is_new = self._add_transaction_hash(tx)
		if is_new:
			self._gossip_transaction(payload, peer)
		self.ez_send(peer, SubmitTransactionResponsePayload(True, tx_digest, message))

	@lazy_wrapper(SubmitTransactionResponsePayload)
	def on_submit_transaction_response(self, peer: Peer, payload: SubmitTransactionResponsePayload):
		if not self._is_approved_peer(peer):
			return
		self.last_tx_response = payload

	@lazy_wrapper(GetChainHeightPayload)
	def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload):
		if not self._is_approved_peer(peer):
			return
		height = self.blockchain.chain_height
		self.ez_send(peer, ChainHeightResponsePayload(payload.request_id, height, self.blockchain.tip))

	@lazy_wrapper(ChainHeightResponsePayload)
	def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponsePayload):
		if not self._is_approved_peer(peer):
			return
		if len(payload.tip_hash) != HASH_SIZE:
			return
		self.peer_heights[peer.public_key.key_to_bin().hex()] = (payload.height, payload.tip_hash)
		# Catch up if this peer is ahead, or on a same-height fork our tie-break prefers.
		our_h = self.blockchain.chain_height
		if payload.height > our_h or (payload.height == our_h and payload.tip_hash < self.blockchain.tip):
			self._fetch_from(peer, payload.height)

	@lazy_wrapper(GetBlockPayload)
	def on_get_block(self, peer: Peer, payload: GetBlockPayload):
		if not self._is_approved_peer(peer):
			return
		if payload.height < 0 or payload.height > self.blockchain.chain_height:
			return

		block = self.blockchain.store.get_block_by_height(payload.height)
		if block is None:
			return
		self.ez_send(
			peer,
			BlockResponsePayload(
				payload.height,
				block.header.prev_hash,
				block.header.txs_hash,
				block.header.timestamp,
				block.header.difficulty,
				block.header.nonce,
				block.header.hash(),
				b"".join(block.tx_hashes),
			),
		)

	@lazy_wrapper(BlockResponsePayload)
	def on_block_response(self, peer: Peer, payload: BlockResponsePayload):
		if not self._is_approved_peer(peer):
			return
		if len(payload.prev_hash) != HASH_SIZE or len(payload.txs_hash) != HASH_SIZE:
			return
		if len(payload.block_hash) != HASH_SIZE:
			return
		try:
			body_hashes = split_tx_hashes(payload.tx_hashes)
		except ValueError:
			return

		header = BlockHeader(
			prev_hash=payload.prev_hash,
			txs_hash=payload.txs_hash,
			timestamp=payload.timestamp,
			difficulty=payload.difficulty,
			nonce=payload.nonce,
		)
		try:
			computed_hash = header.hash()
		except ValueError:
			# Out-of-range timestamp/difficulty/nonce on the wire (signed q fields).
			return
		if computed_hash != payload.block_hash:
			return

		self.add_block(Block(header=header, tx_hashes=body_hashes))

	@lazy_wrapper(TransactionGossipPayload)
	def on_transaction_gossip(self, peer: Peer, payload: TransactionGossipPayload):
		if not self._is_approved_peer(peer):
			return

		success, tx_digest, _message = self._validate_transaction_payload(payload)
		if not success:
			return

		tx: Tx = (payload.sender_key, payload.data, payload.timestamp, payload.signature)

		if self._add_transaction_hash(tx):
			self._gossip_transaction(payload, peer)

	@lazy_wrapper(CheckpointProposalPayload)
	def on_checkpoint_proposal(self, peer: Peer, payload: CheckpointProposalPayload):
		if not self._is_checkpoint_peer(peer):
			return

		ack = self._make_checkpoint_ack(
			payload.height,
			payload.block_hash,
			payload.previous_height,
			payload.previous_hash,
		)
		if ack is None:
			return
		self._record_checkpoint_ack(ack)
		self._broadcast_checkpoint_ack(ack)

	@lazy_wrapper(CheckpointAckPayload)
	def on_checkpoint_ack(self, peer: Peer, payload: CheckpointAckPayload):
		if not self._is_checkpoint_peer(peer):
			return
		if payload.signer_key != peer.public_key.key_to_bin():
			return
		self._record_checkpoint_ack(payload)
