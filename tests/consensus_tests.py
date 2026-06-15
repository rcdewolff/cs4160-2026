import asyncio
import hashlib

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.test.base import TestBase

import blockchain_community
from blockchain_community import (
	BlockChainCommunitySettings,
	BlockchainCommunity,
	SubmitTransactionPayload,
)
from blockchain_utils import Block, BlockHeader, mine_nonce, tx_hash, txs_hash
from mempool import Tx


def make_block(parent_hash, tx_hashes, difficulty, timestamp):
	"""Mine a valid block on top of parent_hash. Cheap at the difficulty=1 used in tests."""
	commit = txs_hash(tx_hashes)
	nonce, _ = mine_nonce(parent_hash, commit, timestamp, difficulty)
	header = BlockHeader(parent_hash, commit, timestamp, difficulty, nonce)
	return Block(header=header, tx_hashes=list(tx_hashes))


def tx_height(node, txh):
	for height, block in enumerate(node.blockchain.chain):
		if txh in block.tx_hashes:
			return height
	return None


class ConsensusLogicTests(TestBase[BlockchainCommunity]):
	"""add_block / reorg / mempool logic, exercised directly (no networking, no mining loop)."""

	def setUp(self):
		super().setUp()
		self._orig_difficulty = blockchain_community.DIFFICULTY
		blockchain_community.DIFFICULTY = 1
		self.initialize(
			overlay_class=BlockchainCommunity,
			node_count=2,
			settings=BlockChainCommunitySettings(allowed_key_hexes=set()),
		)

	async def tearDown(self):
		blockchain_community.DIFFICULTY = self._orig_difficulty
		await super().tearDown()

	def test_genesis_consistency(self):
		tips = {self.overlay(i).blockchain.tip for i in range(2)}
		self.assertEqual(len(tips), 1)
		for i in range(2):
			self.assertEqual(len(self.overlay(i).blockchain.chain), 1)
			self.assertEqual(self.overlay(i).blockchain.height_by_hash[self.overlay(i).blockchain.tip], 0)

	def test_add_block_extends(self):
		node = self.overlay(0)
		genesis = node.blockchain.tip
		block = make_block(genesis, [], 1, 1000)
		self.assertTrue(node.add_block(block))
		self.assertEqual(len(node.blockchain.chain), 2)
		self.assertEqual(node.blockchain.tip, block.header.hash())
		self.assertEqual(node.blockchain.height_by_hash[node.blockchain.tip], 1)
		# Re-adding the same block is a no-op.
		self.assertFalse(node.add_block(block))
		self.assertEqual(len(node.blockchain.chain), 2)

	def test_reorg_longer_chain_wins_out_of_order(self):
		node = self.overlay(0)
		g = node.blockchain.tip
		a1 = make_block(g, [], 1, 1000)
		b1 = make_block(g, [], 1, 2000)
		b2 = make_block(b1.header.hash(), [], 1, 2001)

		node.add_block(a1)
		self.assertEqual(node.blockchain.tip, a1.header.hash())

		# b2 arrives before its parent b1 -> buffered as an orphan, tip unchanged.
		node.add_block(b2)
		self.assertEqual(node.blockchain.tip, a1.header.hash())
		self.assertIn(b2.header.hash(), node.pending_blocks)

		# b1 arrives -> connects b2 -> fork B is longer -> reorg.
		node.add_block(b1)
		self.assertEqual(node.blockchain.tip, b2.header.hash())
		self.assertEqual(len(node.blockchain.chain), 3)
		self.assertEqual(node.pending_blocks, {})

	def test_tie_break_is_deterministic(self):
		g = self.overlay(0).blockchain.tip
		x = make_block(g, [], 1, 1000)
		y = make_block(g, [], 1, 1001)
		winner = min(x.header.hash(), y.header.hash())

		n0, n1 = self.overlay(0), self.overlay(1)
		n0.add_block(x)
		n0.add_block(y)
		# Opposite delivery order on the other node.
		n1.add_block(y)
		n1.add_block(x)

		self.assertEqual(n0.blockchain.tip, winner)
		self.assertEqual(n1.blockchain.tip, winner)

	def test_reorg_returns_tx_to_mempool(self):
		node = self.overlay(0)
		g = node.blockchain.tip
		tx: Tx = (b"sender-key", b"data", 1, b"signature")
		txid = tx_hash(tx[0], tx[1], tx[2], tx[3])
		# txh = hashlib.sha256(b"the-test-transaction").digest()
		# node.known_txs.add(txh)
		# node._tx_order.append(txh)
		# node.mempool = [txh]
		# node.mempool_set = {txh}
		node.mempool.add(tx)

		# Fork A buries the tx at height 1.
		a1 = make_block(g, [txid], 1, 1000)
		node.add_block(a1)
		self.assertEqual(node.blockchain.tip, a1.header.hash())
		self.assertNotIn(txid, node.mempool.free_txs)

		# Longer fork B without the tx wins -> tx must come back to the mempool.
		b1 = make_block(g, [], 1, 2000)
		b2 = make_block(b1.header.hash(), [], 1, 2001)
		node.add_block(b1)
		node.add_block(b2)
		self.assertEqual(node.blockchain.tip, b2.header.hash())
		self.assertIn(txid, node.mempool.free_txs)

	def test_orphan_buffer_connects_in_order(self):
		node = self.overlay(0)
		g = node.blockchain.tip
		b1 = make_block(g, [], 1, 1000)
		b2 = make_block(b1.header.hash(), [], 1, 1001)
		b3 = make_block(b2.header.hash(), [], 1, 1002)

		node.add_block(b3)
		node.add_block(b2)
		self.assertEqual(node.blockchain.tip, g)
		self.assertEqual(len(node.pending_blocks), 2)

		node.add_block(b1)
		self.assertEqual(node.blockchain.tip, b3.header.hash())
		self.assertEqual(len(node.blockchain.chain), 4)
		self.assertEqual(node.pending_blocks, {})

	def test_difficulty_floor_rejects_weak_block(self):
		node = self.overlay(0)
		g = node.blockchain.tip
		weak = make_block(g, [], 0, 1000)  # difficulty 0 is below the shared floor of 1
		self.assertFalse(node.add_block(weak))
		self.assertEqual(node.blockchain.tip, g)

	def test_body_commitment_mismatch_rejected(self):
		node = self.overlay(0)
		g = node.blockchain.tip
		txh = hashlib.sha256(b"x").digest()
		good = make_block(g, [txh], 1, 1000)
		# Keep the (valid PoW) header but swap the body so txs_hash no longer matches.
		tampered = Block(header=good.header, tx_hashes=[hashlib.sha256(b"y").digest()])
		self.assertFalse(node.add_block(tampered))
		self.assertEqual(node.blockchain.tip, g)


class ConsensusNetworkTests(TestBase[BlockchainCommunity]):
	"""Server-facing handler + pull-sync over the mock network (no mining loop running)."""

	def setUp(self):
		super().setUp()
		self._orig_difficulty = blockchain_community.DIFFICULTY
		blockchain_community.DIFFICULTY = 1
		self.initialize(
			overlay_class=BlockchainCommunity,
			node_count=2,
			settings=BlockChainCommunitySettings(allowed_key_hexes=set()),
		)
		keys = {self.overlay(i).my_peer.public_key.key_to_bin().hex() for i in range(2)}
		for i in range(2):
			self.overlay(i).allowed_key_hexes |= keys

	async def tearDown(self):
		blockchain_community.DIFFICULTY = self._orig_difficulty
		await super().tearDown()

	async def test_submit_transaction_accepted(self):
		await self.introduce_nodes()
		sender_key = self.key_bin(1)
		data = b"hello"
		ts = 1_700_000_000
		signature = default_eccrypto.create_signature(
			self.private_key(1), sender_key + data + ts.to_bytes(8, "big", signed=False)
		)
		self.overlay(1).ez_send(self.peer(0), SubmitTransactionPayload(sender_key, data, ts, signature))
		await self.deliver_messages(timeout=0.5)

		expected = tx_hash(sender_key, data, ts, signature)
		self.assertIn(expected, self.overlay(0).mempool.free_txs)
		self.assertTrue(expected, self.overlay(0).mempool.is_known_tx(expected))

		response = self.overlay(1).last_tx_response
		self.assertIsNotNone(response)
		self.assertTrue(response.success)
		self.assertEqual(response.tx_hash, expected)

	async def test_invalid_signature_rejected(self):
		await self.introduce_nodes()
		sender_key = self.key_bin(1)
		data = b"hello"
		ts = 1_700_000_000
		bad_signature = b"\x00" * 64
		self.overlay(1).ez_send(self.peer(0), SubmitTransactionPayload(sender_key, data, ts, bad_signature))
		await self.deliver_messages(timeout=0.5)

		self.assertEqual(self.overlay(0).mempool.free_txs, dict())
		self.assertIsNotNone(self.overlay(1).last_tx_response)
		self.assertFalse(self.overlay(1).last_tx_response.success)

	async def test_pull_sync_converges(self):
		await self.introduce_nodes()
		n0, n1 = self.overlay(0), self.overlay(1)

		prev, ts = n0.blockchain.tip, 1000
		for _ in range(3):
			block = make_block(prev, [], 1, ts)
			ts += 1
			n0.add_block(block)
			prev = block.header.hash()
		self.assertEqual(len(n0.blockchain.chain), 4)
		self.assertEqual(len(n1.blockchain.chain), 1)

		# First tick learns n0's height; second tick fetches the missing blocks.
		await n1._sync_step()
		await self.deliver_messages(timeout=0.5)
		await n1._sync_step()
		await self.deliver_messages(timeout=0.5)

		self.assertEqual(n1.blockchain.tip, n0.blockchain.tip)
		self.assertEqual(len(n1.blockchain.chain), 4)
		for h in range(4):
			self.assertEqual(n0.blockchain.chain[h].header.hash(), n1.blockchain.chain[h].header.hash())


class ConsensusMiningConvergenceTests(TestBase[BlockchainCommunity]):
	"""End-to-end: three nodes mine + sync and must converge, burying an injected tx >= 3 deep."""

	def setUp(self):
		super().setUp()
		self._saved = {
			name: getattr(blockchain_community, name)
			for name in ("DIFFICULTY", "SYNC_INTERVAL", "SYNC_DELAY", "BLOCK_INTERVAL_RANGE")
		}
		# Fast, low-fork settings: block time slightly above the sync interval so a block usually
		# propagates (also pushed on mine) before the next one is mined.
		blockchain_community.DIFFICULTY = 1
		blockchain_community.SYNC_INTERVAL = 0.15
		blockchain_community.SYNC_DELAY = 0.15
		blockchain_community.BLOCK_INTERVAL_RANGE = (0.15, 0.35)
		self.initialize(
			overlay_class=BlockchainCommunity,
			node_count=3,
			settings=BlockChainCommunitySettings(allowed_key_hexes=set()),
		)
		keys = {self.overlay(i).my_peer.public_key.key_to_bin().hex() for i in range(3)}
		for i in range(3):
			self.overlay(i).allowed_key_hexes |= keys

	async def tearDown(self):
		for name, value in self._saved.items():
			setattr(blockchain_community, name, value)
		await super().tearDown()

	def _heights(self):
		return [self.overlay(i).blockchain.height_by_hash[self.overlay(i).blockchain.tip] for i in range(3)]

	async def _run_until(self, predicate, timeout):
		loop = asyncio.get_event_loop()
		deadline = loop.time() + timeout
		while loop.time() < deadline:
			await asyncio.sleep(0.2)
			if predicate():
				return True
		return False

	async def test_three_node_convergence_with_tx(self):
		await self.introduce_nodes()
		for i in range(3):
			self.overlay(i).started()

		# Let the three chains grow and converge.
		grew = await self._run_until(lambda: min(self._heights()) >= 4, timeout=20)
		self.assertTrue(grew, f"chains did not grow: heights={self._heights()}")

		# Inject a transaction at one node; it must be mined in and propagate to all three.
		node0 = self.overlay(0)
		tx = (b"some-sender", b"some-data", 100, b"some-signature")
		txh = tx_hash(tx[0], tx[1], tx[2], tx[3])
		node0.mempool.add(tx)

		def buried_everywhere():
			heights = [tx_height(self.overlay(i), txh) for i in range(3)]
			if any(h is None for h in heights):
				return False
			if len(set(heights)) != 1:  # same height on every node
				return False
			return all(
				self.overlay(i).blockchain.height_by_hash[self.overlay(i).blockchain.tip] - heights[i] >= 3
				for i in range(3)
			)

		buried = await self._run_until(buried_everywhere, timeout=20)
		self.assertTrue(buried, "tx was not buried >=3 deep consistently on all nodes")
		# Consistency: every node agrees on the block hash at each confirmed height.
		min_h = min(self._heights())
		confirmed = min_h - 2
		self.assertGreaterEqual(confirmed, 1)
		for h in range(confirmed + 1):
			hashes = {self.overlay(i).blockchain.chain[h].header.hash() for i in range(3)}
			self.assertEqual(len(hashes), 1, f"nodes disagree at height {h}")

		# Body commitment of the tx's block matches the spec recomputation on every node.
		tx_h = tx_height(self.overlay(0), txh)
		for i in range(3):
			block = self.overlay(i).blockchain.chain[tx_h]
			self.assertEqual(txs_hash(block.tx_hashes), block.header.txs_hash)
