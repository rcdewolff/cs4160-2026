import asyncio
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

class BlockChainCommunitySettings(CommunitySettings):
	allowed_key_hexes: set[str]


class BlockchainCommunity(Community):
	community_id = bytes(20)
	settings_class = BlockChainCommunitySettings

	def __init__(self, settings):
		super().__init__(settings)

		self.crypto = default_eccrypto
		self.allowed_key_hexes = set(getattr(settings, "allowed_key_hexes", set()))
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

		self.mempool = Mempool()
		self.blockchain = Blockchain(self._init_genesis(), self.mempool, DIFFICULTY)
		# self.peer_heights = {}

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)
		self.add_message_handler(TransactionGossipPayload, self.on_transaction_gossip)

	def started(self) -> None:
		# Called once by IPv8 after the overlay loads (run_node passes the ("started",) hook).
		self.register_task("mine", self._mine_loop, ignore=(Exception,))
		self.register_task(
			"sync", self._sync_step, interval=SYNC_INTERVAL, delay=SYNC_DELAY, ignore=(Exception,)
		)

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

	# def _block_is_valid(self, bh: bytes, block: Block) -> bool:
	# 	if not has_valid_pow(bh, block.header.difficulty):
	# 		return False
	# 	# Reject anything mined below the shared difficulty (defends against a buggy/cheap peer
	# 	# trying to win the longest-chain race or flood us with trivial blocks).
	# 	if block.header.difficulty < DIFFICULTY:
	# 		return False
	# 	try:
	# 		return txs_hash(block.tx_hashes) == block.header.txs_hash
	# 	except ValueError:
	# 		return False

	# def _store(self, bh: bytes, block: Block, parent: bytes) -> None:
	# 	self.blockchain.add_block(block)
		# self.blocks[bh] = block
		# self.height_by_hash[bh] = self.height_by_hash[parent] + 1

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
				# self._store(oh, orphan, parent)  # orphan already passed _block_is_valid when buffered
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
		# bh = block.header.hash()
		# if bh in self.blocks:
		# 	return False
		# if not self._block_is_valid(bh, block):
		# 	return False

		# parent = block.header.prev_hash
		# if parent not in self.blocks:
		# 	if len(self.pending_blocks) < PENDING_CAP:
		# 		self.pending_blocks[bh] = block
		# 	return False

		# self._store(bh, block, parent)
		# candidates = self._connect_orphans(bh)

		# Longest-chain rule with a deterministic tie-break (smaller block hash wins) so every
		# node converges on the same chain even when two blocks land at the same height.
		# best = self.best_tip
		# best_h = self.height_by_hash[best]
		# for cand in candidates:
		# 	ch = self.height_by_hash[cand]
		# 	if ch > best_h or (ch == best_h and cand < best):
		# 		best, best_h = cand, ch
		# if best != self.best_tip:
		# 	self._set_tip(best)
		# return True

	# def _set_tip(self, new_tip: bytes) -> None:
	# 	# Rebuild the canonical chain by walking parents back to genesis (height strictly
	# 	# decreases each step, so this terminates), then reconcile the mempool.
	# 	chain_rev = []
	# 	node = new_tip
	# 	while True:
	# 		block = self.blocks[node]
	# 		chain_rev.append(block)
	# 		if self.height_by_hash[node] == 0:
	# 			break
	# 		node = block.header.prev_hash
	# 	chain_rev.reverse()
	# 	self.chain = chain_rev
	# 	self.best_tip = new_tip
	# 	self._reconcile_mempool()

	# def _reconcile_mempool(self) -> None:
	# 	on_chain = set()
	# 	for block in self.blockchain.chain:
	# 		on_chain.update(block.tx_hashes)
	# 	self.mempool = [t for t in self._tx_order if t in self.known_txs and t not in on_chain]
	# 	self.mempool_set = set(self.mempool)

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
		# is_new = tx_digest not in self.known_txs
		# if is_new:
		# 	self.known_txs.add(tx_digest)
		# 	self._tx_order.append(tx_digest)
		# if tx_digest not in self.mempool_set:
		# 	self.mempool.append(tx_digest)
		# 	self.mempool_set.add(tx_digest)
		txid, is_new = self.mempool.add(tx)
		return is_new

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

		block = self.blockchain.chain[payload.height]
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
