import asyncio
import random
import time
from collections import deque

from ipv8.community import Community, CommunitySettings
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

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


# Proof-of-work difficulty (leading zero bits) every node mines at. All three nodes MUST share
# this value, the genesis layout, and the community_id, or the longest-chain rule disagrees.
DIFFICULTY = 17
# Nonces tried per synchronous burst before yielding to the event loop. Keeps the CPU-bound miner
# from starving IPv8's UDP receive and the sync loop.
MINE_CHUNK = 20000
# Target time between a node's own blocks (randomized). MUST stay comfortably above block
# propagation latency (~one sync round trip) so the three chains rarely fork.
BLOCK_INTERVAL_RANGE = (1.5, 2.5)
# How often a node polls teammates for their height/tip (safety net; mining also pushes its tip).
SYNC_INTERVAL = 0.5
SYNC_DELAY = 1.0
# When catching up, also refetch a few blocks below our tip so shallow reorgs can find a common
# ancestor, and cap how many blocks we request per peer per tick.
SYNC_DOWN_WINDOW = 16
FETCH_BATCH = 64
# Upper bound on buffered out-of-order (orphan) blocks.
PENDING_CAP = 1000


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
		self.blocks: dict[bytes, Block] = {}
		self.height_by_hash: dict[bytes, int] = {}
		self.best_tip: bytes = b""
		self.chain: list[Block] = []
		self.pending_blocks: dict[bytes, Block] = {}  # orphans keyed by their own block hash

		# Transactions. known_txs is the never-pruned source of truth so a reorg that orphans the
		# test transaction puts it back in the mempool to be re-mined.
		self.known_txs: set[bytes] = set()
		self._tx_order: list[bytes] = []
		self.mempool: list[bytes] = []
		self.mempool_set: set[bytes] = set()

		# Peer sync state.
		self.peer_heights: dict[str, tuple[int, bytes]] = {}
		self._req_counter = 0
		self.last_tx_response = None

		self._init_genesis()

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)

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

	def _init_genesis(self) -> None:
		genesis_header = BlockHeader(
			prev_hash=b"\x00" * HASH_SIZE,
			txs_hash=txs_hash([]),
			timestamp=0,
			difficulty=0,
			nonce=0,
		)
		genesis = Block(header=genesis_header, tx_hashes=[])
		gh = genesis_header.hash()
		self.blocks[gh] = genesis
		self.height_by_hash[gh] = 0
		self.best_tip = gh
		self.chain = [genesis]

	# --- Consensus core --------------------------------------------------------------------

	def _block_is_valid(self, bh: bytes, block: Block) -> bool:
		if not has_valid_pow(bh, block.header.difficulty):
			return False
		# Reject anything mined below the shared difficulty (defends against a buggy/cheap peer
		# trying to win the longest-chain race or flood us with trivial blocks).
		if block.header.difficulty < DIFFICULTY:
			return False
		try:
			return txs_hash(block.tx_hashes) == block.header.txs_hash
		except ValueError:
			return False

	def _store(self, bh: bytes, block: Block, parent: bytes) -> None:
		self.blocks[bh] = block
		self.height_by_hash[bh] = self.height_by_hash[parent] + 1

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
				if oh in self.blocks:
					continue
				self._store(oh, orphan, parent)  # orphan already passed _block_is_valid when buffered
				connected.append(oh)
				work.append(oh)
		return connected

	def add_block(self, block: Block) -> bool:
		"""Validate and integrate a block. Handles dedup, orphan buffering, fork choice and reorg.

		Synchronous on purpose: both the miner and the network path call it, and running it to
		completion between event-loop yields keeps the chain state consistent without locks.
		"""
		bh = block.header.hash()
		if bh in self.blocks:
			return False
		if not self._block_is_valid(bh, block):
			return False

		parent = block.header.prev_hash
		if parent not in self.blocks:
			if len(self.pending_blocks) < PENDING_CAP:
				self.pending_blocks[bh] = block
			return False

		self._store(bh, block, parent)
		candidates = self._connect_orphans(bh)

		# Longest-chain rule with a deterministic tie-break (smaller block hash wins) so every
		# node converges on the same chain even when two blocks land at the same height.
		best = self.best_tip
		best_h = self.height_by_hash[best]
		for cand in candidates:
			ch = self.height_by_hash[cand]
			if ch > best_h or (ch == best_h and cand < best):
				best, best_h = cand, ch
		if best != self.best_tip:
			self._set_tip(best)
		return True

	def _set_tip(self, new_tip: bytes) -> None:
		# Rebuild the canonical chain by walking parents back to genesis (height strictly
		# decreases each step, so this terminates), then reconcile the mempool.
		chain_rev = []
		node = new_tip
		while True:
			block = self.blocks[node]
			chain_rev.append(block)
			if self.height_by_hash[node] == 0:
				break
			node = block.header.prev_hash
		chain_rev.reverse()
		self.chain = chain_rev
		self.best_tip = new_tip
		self._reconcile_mempool()

	def _reconcile_mempool(self) -> None:
		on_chain = set()
		for block in self.chain:
			on_chain.update(block.tx_hashes)
		self.mempool = [t for t in self._tx_order if t in self.known_txs and t not in on_chain]
		self.mempool_set = set(self.mempool)

	# --- Mining ----------------------------------------------------------------------------

	async def _mine_loop(self) -> None:
		while True:
			try:
				parent = self.best_tip
				body = list(self.mempool)
				commit = txs_hash(body)
				timestamp = int(time.time())
				difficulty = DIFFICULTY
				nonce = 0
				mined = None

				# Mine in chunks, yielding to the loop between them and aborting if a better tip
				# arrives (which also changes the mempool we should be mining).
				while self.best_tip == parent:
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

				if mined is not None and self.best_tip == parent:
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
		height = self.height_by_hash[self.best_tip]
		for peer in self._teammate_peers():
			self.ez_send(peer, ChainHeightResponsePayload(0, height, self.best_tip))

	def _fetch_from(self, peer: Peer, their_h: int) -> None:
		our_h = self.height_by_hash[self.best_tip]
		start = max(0, our_h - SYNC_DOWN_WINDOW)
		end = min(their_h, our_h + FETCH_BATCH)
		for height in range(start, end + 1):
			self.ez_send(peer, GetBlockPayload(height))

	# --- Message handlers ------------------------------------------------------------------

	@lazy_wrapper(SubmitTransactionPayload)
	def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload):
		if not self._is_approved_peer(peer):
			return

		if payload.timestamp < 0:
			self.ez_send(peer, SubmitTransactionResponsePayload(False, b"", "bad timestamp"))
			return

		message = (
			payload.sender_key
			+ payload.data
			+ payload.timestamp.to_bytes(8, "big", signed=False)
		)
		try:
			signer_key = self.crypto.key_from_public_bin(payload.sender_key)
		except Exception:
			self.ez_send(peer, SubmitTransactionResponsePayload(False, b"", "bad sender key"))
			return

		if not self.crypto.is_valid_signature(signer_key, message, payload.signature):
			self.ez_send(peer, SubmitTransactionResponsePayload(False, b"", "invalid signature"))
			return

		tx_digest = tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature)
		if tx_digest not in self.known_txs:
			self.known_txs.add(tx_digest)
			self._tx_order.append(tx_digest)
		if tx_digest not in self.mempool_set:
			self.mempool.append(tx_digest)
			self.mempool_set.add(tx_digest)
		self.ez_send(peer, SubmitTransactionResponsePayload(True, tx_digest, "accepted"))

	@lazy_wrapper(SubmitTransactionResponsePayload)
	def on_submit_transaction_response(self, peer: Peer, payload: SubmitTransactionResponsePayload):
		if not self._is_approved_peer(peer):
			return
		self.last_tx_response = payload

	@lazy_wrapper(GetChainHeightPayload)
	def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload):
		if not self._is_approved_peer(peer):
			return
		height = self.height_by_hash[self.best_tip]
		self.ez_send(peer, ChainHeightResponsePayload(payload.request_id, height, self.best_tip))

	@lazy_wrapper(ChainHeightResponsePayload)
	def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponsePayload):
		if not self._is_approved_peer(peer):
			return
		if len(payload.tip_hash) != HASH_SIZE:
			return
		self.peer_heights[peer.public_key.key_to_bin().hex()] = (payload.height, payload.tip_hash)
		# Catch up if this peer is ahead, or on a same-height fork our tie-break prefers.
		our_h = self.height_by_hash[self.best_tip]
		if payload.height > our_h or (payload.height == our_h and payload.tip_hash < self.best_tip):
			self._fetch_from(peer, payload.height)

	@lazy_wrapper(GetBlockPayload)
	def on_get_block(self, peer: Peer, payload: GetBlockPayload):
		if not self._is_approved_peer(peer):
			return
		if payload.height < 0 or payload.height >= len(self.chain):
			return

		block = self.chain[payload.height]
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
