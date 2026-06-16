import asyncio

import blockchain_community
from ipv8.test.base import TestBase
from blockchain_community import BlockchainCommunity, BlockChainCommunitySettings
from blockchain_utils import txs_hash, tx_hash, hash_block_header


def tx_height(node, txh):
	for height, block in enumerate(node.blockchain.chain):
		if txh in block.tx_hashes:
			return height
	return None


class ConsensusPruningReorgTests(TestBase[BlockchainCommunity]):
	"""End-to-end: three nodes mine while pruning runs; a network partition forces a
	genuine multi-block reorg; the cluster must reconverge with the header backbone
	fully intact and bodies pruned consistently on every node.

	Parameters keep PRUNE_DEPTH > SYNC_DOWN_WINDOW (the serving invariant), so the
	fork created here stays inside the kept/servable window. The complementary case
	-- a fork *below* the prune floor -- cannot be exercised over a real network
	(pruned bodies are not servable) and is covered directly by test_deep_reorg.py.
	"""

	PRUNE_DEPTH = 6
	SYNC_WINDOW = 4               # must stay < PRUNE_DEPTH
	GROW_TO = 2 * PRUNE_DEPTH + 2  # tall enough for a guaranteed-pruned region to exist

	def setUp(self):
		super().setUp()
		self._saved = {
			name: getattr(blockchain_community, name)
			for name in ("DIFFICULTY", "SYNC_INTERVAL", "SYNC_DELAY",
						 "BLOCK_INTERVAL_RANGE", "SYNC_DOWN_WINDOW")
		}
		blockchain_community.DIFFICULTY = 1
		blockchain_community.SYNC_INTERVAL = 0.15
		blockchain_community.SYNC_DELAY = 0.15
		blockchain_community.BLOCK_INTERVAL_RANGE = (0.15, 0.35)
		blockchain_community.SYNC_DOWN_WINDOW = self.SYNC_WINDOW
		self.initialize(
			overlay_class=BlockchainCommunity,
			node_count=3,
			settings=BlockChainCommunitySettings(allowed_key_hexes=set(),
												 data_dir="temp"),
		)
		self._keys = {i: self.overlay(i).my_peer.public_key.key_to_bin().hex() for i in range(3)}
		for i in range(3):
			self.overlay(i).allowed_key_hexes |= set(self._keys.values())
			# identical, aggressive prune depth on every node so pruning fires early
			self.overlay(i).blockchain.prune_depth = self.PRUNE_DEPTH

	async def tearDown(self):
		for name, value in self._saved.items():
			setattr(blockchain_community, name, value)
		await super().tearDown()

	# --- helpers ---------------------------------------------------------------
	def _height(self, i):
		bc = self.overlay(i).blockchain
		return bc.height_by_hash[bc.tip]

	def _heights(self):
		return [self._height(i) for i in range(3)]

	def _tip(self, i):
		return self.overlay(i).blockchain.tip

	def _chain_hashes(self, i):
		return [b.header.hash() for b in self.overlay(i).blockchain.chain]

	def _body_at(self, i, h):
		return self.overlay(i).blockchain.store.get_block_by_height(h)

	async def _run_until(self, predicate, timeout):
		loop = asyncio.get_event_loop()
		deadline = loop.time() + timeout
		while loop.time() < deadline:
			await asyncio.sleep(0.2)
			if predicate():
				return True
		return False

	def _partition(self, group_a, group_b):
		for i in group_a:
			for j in group_b:
				self.overlay(i).allowed_key_hexes.discard(self._keys[j])
				self.overlay(j).allowed_key_hexes.discard(self._keys[i])

	def _heal(self):
		allkeys = set(self._keys.values())
		for i in range(3):
			self.overlay(i).allowed_key_hexes |= allkeys

	def _freeze(self):
		for i in range(3):
			for task in ("mine", "sync"):
				try:
					self.overlay(i).cancel_pending_task(task)
				except KeyError:
					pass

	def _assert_header_backbone(self, i):
		bc = self.overlay(i).blockchain
		log = bc.store.headers
		self.assertEqual(log.count, bc.chain_height + 1,
						 f"node {i}: header log out of sync with chain")
		prev = b"\x00" * 32
		for h in range(log.count):
			bh, hdr = log.get(h)
			self.assertEqual(hash_block_header(hdr), bh, f"node {i}: header {h} hash mismatch")
			if h > 0:
				self.assertEqual(hdr[:32], prev, f"node {i}: header {h} broken parent link")
			self.assertEqual(bh, bc.chain[h].header.hash(),
							 f"node {i}: header log != main chain at {h}")
			prev = bh

	# --- the test --------------------------------------------------------------
	async def test_pruning_survives_partition_reorg(self):
		await self.introduce_nodes()
		for i in range(3):
			self.overlay(i).started()

		# Phase 1: grow tall enough that pruning is firing on buried history.
		grew = await self._run_until(lambda: min(self._heights()) >= self.GROW_TO, timeout=40)
		self.assertTrue(grew, f"chains did not grow: {self._heights()}")

		# Phase 2: partition {0,1} | {2}; mine independently until both sides have
		# diverged by >= 2 blocks (a genuine multi-block fork, kept shallow so it
		# stays inside the serving window for reconvergence).
		base = min(self._heights())
		self._partition([0, 1], [2])
		diverged = await self._run_until(
			lambda: self._height(2) >= base + 2
			and min(self._height(0), self._height(1)) >= base + 2
			and self._tip(2) != self._tip(0) and self._tip(2) != self._tip(1),
			timeout=40,
		)
		self.assertTrue(diverged, f"partition did not diverge: {self._heights()}")
		pre = {i: self._chain_hashes(i) for i in range(3)}     # snapshot the fork
		self.assertNotEqual(pre[2][-1], pre[0][-1], "no divergence across the partition")

		# Phase 3: heal and require full reconvergence.
		self._heal()
		converged = await self._run_until(
			lambda: len({self._tip(i) for i in range(3)}) == 1, timeout=40)
		self.assertTrue(converged,
						f"did not reconverge: heights={self._heights()} "
						f"tips={[self._tip(i).hex()[:8] for i in range(3)]}")
		final = self._chain_hashes(0)

		# A real multi-block reorg must have replaced some node's pre-heal branch.
		max_rollback = 0
		for i in range(3):
			snap = pre[i]
			fork = 0
			while fork < min(len(snap), len(final)) and snap[fork] == final[fork]:
				fork += 1
			if fork < len(snap):
				max_rollback = max(max_rollback, len(snap) - fork)
		self.assertGreaterEqual(max_rollback, 2, "expected a multi-block reorg across the partition")

		# Phase 4: the merged chain is still live -- a fresh tx mines in everywhere.
		tx = (b"after-reorg", b"payload", 100, b"sig")
		txh = tx_hash(*tx)
		self.overlay(0).mempool.add(tx)

		def buried_everywhere():
			hs = [tx_height(self.overlay(i), txh) for i in range(3)]
			if any(x is None for x in hs) or len(set(hs)) != 1:
				return False
			return all(self._height(i) - hs[i] >= 2 for i in range(3))

		self.assertTrue(await self._run_until(buried_everywhere, timeout=40),
						"post-reorg tx was not buried consistently on all nodes")

		# Phase 5: freeze mining and inspect the now-static state.
		self._freeze()
		await self.deliver_messages(timeout=0.5)
		self.assertEqual(len({self._tip(i) for i in range(3)}), 1, "tips diverged after freeze")

		heights = self._heights()
		self.assertEqual(len(set(heights)), 1, f"heights disagree: {heights}")
		tip_h = heights[0]
		depth = self.PRUNE_DEPTH

		# (1) every node agrees on the block hash at every height (full consistency)
		for h in range(tip_h + 1):
			hs = {self.overlay(i).blockchain.chain[h].header.hash() for i in range(3)}
			self.assertEqual(len(hs), 1, f"nodes disagree at height {h}")

		# (2) the verifiable header backbone is intact on every node
		for i in range(3):
			self._assert_header_backbone(i)

		# (3) bodies inside the kept/serving window are present on every node
		for i in range(3):
			for h in range(tip_h - depth + 1, tip_h + 1):
				self.assertIsNotNone(self._body_at(i, h),
									 f"node {i}: missing body inside kept window at {h}")

		# (4) pruning actually fired: each node dropped buried bodies but kept headers
		for i in range(3):
			pruned = [h for h in range(1, tip_h - depth + 1) if self._body_at(i, h) is None]
			self.assertTrue(pruned, f"node {i}: nothing pruned below the floor")
			for h in pruned:
				self.assertIsNotNone(self.overlay(i).blockchain.store.headers.get(h),
									 f"node {i}: pruned away a header at {h} (chain unverifiable)")

		# (5) determinism bracket: the deeply-buried region is gone on EVERY node.
		# Compaction throttling makes the exact floor node-local, but every node's
		# kept set is a suffix [floor_i, tip] with floor_i >= tip - 2*depth + 1, so
		# everything below tip - 2*depth is guaranteed pruned identically everywhere.
		guaranteed_top = tip_h - 2 * depth
		self.assertGreaterEqual(guaranteed_top, 1, "test too short to bracket determinism")
		for h in range(1, guaranteed_top + 1):
			for i in range(3):
				self.assertIsNone(self._body_at(i, h),
								  f"node {i}: body at {h} should be pruned on all nodes")

		# (6) body commitment of the tx's block matches the spec recomputation
		tx_blk_h = tx_height(self.overlay(0), txh)
		for i in range(3):
			blk = self.overlay(i).blockchain.chain[tx_blk_h]
			self.assertEqual(txs_hash(blk.tx_hashes), blk.header.txs_hash)