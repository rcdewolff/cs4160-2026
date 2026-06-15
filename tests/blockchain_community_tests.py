from ipv8.keyvault.crypto import default_eccrypto
from ipv8.test.base import TestBase

import blockchain_community
from blockchain_community import (
	ASSIGNMENT_MESSAGE_PAYLOADS,
	BlockChainCommunitySettings,
	BlockchainCommunity,
	BlockResponsePayload,
	SubmitTransactionPayload,
	TransactionGossipPayload,
)
from blockchain_utils import Block, BlockHeader, HASH_SIZE, mine_nonce, tx_hash, txs_hash


def make_block(parent_hash: bytes, tx_hashes: list[bytes], difficulty: int, timestamp: int) -> Block:
	commit = txs_hash(tx_hashes)
	nonce, _ = mine_nonce(parent_hash, commit, timestamp, difficulty, max_attempts=1)
	header = BlockHeader(parent_hash, commit, timestamp, difficulty, nonce)
	return Block(header=header, tx_hashes=list(tx_hashes))


class BlockchainCommunityTests(TestBase[BlockchainCommunity]):
	def setUp(self):
		super().setUp()
		self._orig_difficulty = blockchain_community.DIFFICULTY
		blockchain_community.DIFFICULTY = 0
		self.initialize(
			overlay_class=BlockchainCommunity,
			node_count=3,
			settings=BlockChainCommunitySettings(allowed_key_hexes=set()),
		)
		keys = {self.overlay(i).my_peer.public_key.key_to_bin().hex() for i in range(3)}
		for i in range(3):
			self.overlay(i).allowed_key_hexes |= keys

	async def tearDown(self):
		blockchain_community.DIFFICULTY = self._orig_difficulty
		await super().tearDown()

	def test_assignment_message_ids_and_genesis(self):
		self.assertEqual([payload.msg_id for payload in ASSIGNMENT_MESSAGE_PAYLOADS], [1, 2, 3, 4, 5, 6])
		self.assertEqual([payload.msg_id for payload in [TransactionGossipPayload]], [7])
		node = self.overlay(0)
		self.assertEqual(len(node.blockchain.chain), 1)
		self.assertEqual(node.blockchain.height_by_hash[node.blockchain.tip], 0)
		self.assertEqual(node.blockchain.chain[0].header.prev_hash, b"\x00" * HASH_SIZE)
		self.assertEqual(node.blockchain.chain[0].header.txs_hash, txs_hash([]))

	async def test_submit_transaction_accepts_valid_signature_and_gossips(self):
		sender_key = self.key_bin(0)
		data = b"lab3-test-tx"
		timestamp = 123
		message = sender_key + data + timestamp.to_bytes(8, "big", signed=False)
		signature = default_eccrypto.create_signature(self.private_key(0), message)
		expected_hash = tx_hash(sender_key, data, timestamp, signature)

		with self.assertReceivedBy(2, [TransactionGossipPayload]):
			self.overlay(0).ez_send(
				self.peer(1),
				SubmitTransactionPayload(sender_key, data, timestamp, signature),
			)
			await self.deliver_messages(timeout=0.5)

		self.assertIn(expected_hash, self.overlay(1).mempool.free_txs)
		self.assertIn(expected_hash, self.overlay(2).mempool.free_txs)
		self.assertTrue(self.overlay(0).last_tx_response.success)
		self.assertEqual(self.overlay(0).last_tx_response.tx_hash, expected_hash)
		self.assertIsNone(self.overlay(1).last_tx_response)
		self.assertIsNone(self.overlay(2).last_tx_response)

	async def test_duplicate_transaction_is_not_re_gossiped_or_reordered(self):
		sender_key = self.key_bin(0)
		data = b"lab3-test-tx"
		timestamp = 123
		message = sender_key + data + timestamp.to_bytes(8, "big", signed=False)
		signature = default_eccrypto.create_signature(self.private_key(0), message)
		payload = SubmitTransactionPayload(sender_key, data, timestamp, signature)
		expected_hash = tx_hash(sender_key, data, timestamp, signature)

		self.overlay(0).ez_send(self.peer(1), payload)
		await self.deliver_messages(timeout=0.5)
		self.overlay(0).ez_send(self.peer(1), payload)
		await self.deliver_messages(timeout=0.5)

		self.assertEqual(self.overlay(1).mempool.tx_order.count(expected_hash), 1)
		self.assertEqual(self.overlay(2).mempool.tx_order.count(expected_hash), 1)

	async def test_invalid_signature_is_rejected(self):
		self.overlay(0).ez_send(
			self.peer(1),
			SubmitTransactionPayload(self.key_bin(0), b"bad", 123, b"bad signature"),
		)
		await self.deliver_messages(timeout=0.5)

		self.assertEqual(self.overlay(1).mempool.free_txs, dict())
		self.assertEqual(self.overlay(2).mempool.free_txs, dict())
		self.assertFalse(self.overlay(0).last_tx_response.success)

	async def test_block_response_adds_valid_block(self):
		node0 = self.overlay(0)
		node1 = self.overlay(1)
		block = make_block(node0.blockchain.tip, [], 0, 1)
		payload = BlockResponsePayload(
			1,
			block.header.prev_hash,
			block.header.txs_hash,
			block.header.timestamp,
			block.header.difficulty,
			block.header.nonce,
			block.header.hash(),
			b"".join(block.tx_hashes),
		)

		node0.ez_send(self.peer(1), payload)
		await self.deliver_messages(timeout=0.5)

		self.assertEqual(node1.blockchain.tip, block.header.hash())
		self.assertEqual(len(node1.blockchain.chain), 2)

	def test_equal_height_tie_break_uses_smaller_hash(self):
		node = self.overlay(0)
		x = make_block(node.blockchain.tip, [], 0, 1)
		y = make_block(node.blockchain.tip, [], 0, 2)
		expected_tip = min(x.header.hash(), y.header.hash())

		node.add_block(x)
		node.add_block(y)

		self.assertEqual(node.blockchain.tip, expected_tip)
