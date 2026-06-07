from ipv8.test.base import TestBase

from blockchain_community import (
    ASSIGNMENT_MESSAGE_PAYLOADS,
    BlockChainCommunitySettings,
    BlockchainCommunity,
    BlockResponsePayload,
    GetChainHeightPayload,
    SubmitTransactionPayload,
)
from blockchain_utils import HASH_SIZE, BlockHeader, block_hash, tx_hash, txs_hash


class BlockchainCommunityTests(TestBase[BlockchainCommunity]):
    def setUp(self):
        super().setUp()
        self.initialize(
            overlay_class=BlockchainCommunity,
            node_count=4,
            settings=BlockChainCommunitySettings(
                allowed_key_hexes=set(),
                member_key_hexes=[],
                difficulty=0,
                enable_mining=False,
                mine_batch_size=100,
                sync_interval=60.0,
                max_sync_blocks=64,
            ),
        )

    def test_community_initialization(self):
        first_block = BlockHeader(
            prev_hash=b"\x00" * HASH_SIZE,
            txs_hash=txs_hash([]),
            timestamp=0,
            difficulty=0,
            nonce=0,
        )
        self.assertEqual([payload.msg_id for payload in ASSIGNMENT_MESSAGE_PAYLOADS], [1, 2, 3, 4, 5, 6])
        self.assertEqual(self.overlay(0).allowed_key_hexes, set())
        self.assertEqual(len(self.overlay(0).chain), 1)
        self.assertEqual(self.overlay(0).chain[0].header, first_block)

    async def test_submit_transaction_accepts_valid_signature_and_gossips(self):
        sender_key = self.key_bin(0)
        data = b"lab3-test-tx"
        timestamp = 123
        message = sender_key + data + timestamp.to_bytes(8, "big", signed=False)
        signature = self.overlay(0).crypto.create_signature(self.private_key(0), message)
        expected_hash = tx_hash(sender_key, data, timestamp, signature)

        self.overlay(0).ez_send(
            self.peer(1),
            SubmitTransactionPayload(sender_key, data, timestamp, signature),
        )
        await self.deliver_messages(timeout=0.5)

        self.assertIn(expected_hash, self.overlay(1).mempool_set)
        self.assertIn(expected_hash, self.overlay(2).mempool_set)
        self.assertIn(expected_hash, self.overlay(3).mempool_set)

    async def test_invalid_signature_is_rejected(self):
        sender_key = self.key_bin(0)
        data = b"lab3-test-tx"
        timestamp = 123
        signature = b"bad signature"

        self.overlay(0).ez_send(
            self.peer(1),
            SubmitTransactionPayload(sender_key, data, timestamp, signature),
        )
        await self.deliver_messages(timeout=0.5)

        self.assertEqual(self.overlay(1).mempool, [])
        self.assertFalse(self.overlay(0).last_tx_response.success)

    async def test_mined_block_broadcasts_as_block_response(self):
        block = self.overlay(0).mine_next_block_sync(timestamp=1)
        self.assertIsNotNone(block)

        await self.deliver_messages(timeout=0.5)

        self.assertEqual(self.overlay(0).height(), 1)
        self.assertEqual(self.overlay(1).height(), 1)
        self.assertEqual(self.overlay(2).height(), 1)
        self.assertEqual(self.overlay(0).tip_hash(), self.overlay(1).tip_hash())
        self.assertEqual(self.overlay(0).tip_hash(), self.overlay(2).tip_hash())

    async def test_peer_height_polling_uses_get_chain_height(self):
        with self.assertReceivedBy(1, [GetChainHeightPayload]):
            await self.overlay(0).sync_loop()
            await self.deliver_messages(timeout=0.2)

    async def test_catch_up_uses_get_block_and_block_response(self):
        node0 = self.overlay(0)
        node1 = self.overlay(1)
        original_broadcast = node0.broadcast_block
        node0.broadcast_block = lambda height, block: None
        try:
            node0.mine_next_block_sync(timestamp=1)
            node0.mine_next_block_sync(timestamp=2)
        finally:
            node0.broadcast_block = original_broadcast

        self.assertEqual(node0.height(), 2)
        self.assertEqual(node1.height(), 0)

        await node1.sync_loop()
        await self.deliver_messages(timeout=1.0)

        self.assertEqual(node1.height(), 2)
        self.assertEqual(node1.tip_hash(), node0.tip_hash())

    async def test_accepting_peer_block_interrupts_mining(self):
        node0 = self.overlay(0)
        node1 = self.overlay(1)
        block = node0.mine_next_block_sync(timestamp=1)
        self.assertIsNotNone(block)
        generation_before = node1.mining_generation

        node0.ez_send(self.peer(1), node0._payload_for_block(1, block))
        await self.deliver_messages(timeout=0.5)

        self.assertEqual(node1.height(), 1)
        self.assertGreater(node1.mining_generation, generation_before)

    async def test_equal_height_different_tip_does_not_switch(self):
        node0 = self.overlay(0)
        node1 = self.overlay(1)
        node0.broadcast_block = lambda height, block: None
        node1.broadcast_block = lambda height, block: None

        node0.mine_next_block_sync(timestamp=1)
        node1.mine_next_block_sync(timestamp=2)
        node0_tip = node0.tip_hash()
        node1_tip = node1.tip_hash()
        self.assertNotEqual(node0_tip, node1_tip)

        node0.ez_send(self.peer(1), node0._payload_for_block(1, node0.chain[1]))
        await self.deliver_messages(timeout=0.5)

        self.assertEqual(node1.height(), 1)
        self.assertEqual(node1.tip_hash(), node1_tip)

    async def test_fork_recovery_switches_to_longer_valid_chain(self):
        node0 = self.overlay(0)
        node1 = self.overlay(1)
        node0.broadcast_block = lambda height, block: None
        node1.broadcast_block = lambda height, block: None

        node0.mine_next_block_sync(timestamp=1)
        node0.mine_next_block_sync(timestamp=2)
        node0.mine_next_block_sync(timestamp=3)
        node1.mine_next_block_sync(timestamp=4)
        self.assertEqual(node0.height(), 3)
        self.assertEqual(node1.height(), 1)
        self.assertNotEqual(node0.chain[1].header.hash(), node1.chain[1].header.hash())

        await node1.sync_loop()
        await self.deliver_messages(timeout=1.0)

        self.assertEqual(node1.height(), 3)
        self.assertEqual(node1.tip_hash(), node0.tip_hash())

    async def test_invalid_block_response_is_ignored(self):
        node0 = self.overlay(0)
        node1 = self.overlay(1)
        original_broadcast = node0.broadcast_block
        node0.broadcast_block = lambda height, block: None
        try:
            block = node0.mine_next_block_sync(timestamp=1)
            self.assertIsNotNone(block)
        finally:
            node0.broadcast_block = original_broadcast
        payload = BlockResponsePayload(
            1,
            block.header.prev_hash,
            block.header.txs_hash,
            block.header.timestamp,
            block.header.difficulty,
            block.header.nonce,
            b"\xff" * HASH_SIZE,
            b"".join(block.tx_hashes),
        )

        node0.ez_send(self.peer(1), payload)
        await self.deliver_messages(timeout=0.5)

        self.assertEqual(node1.height(), 0)

    def test_payload_for_block_uses_assignment_hash_formula(self):
        node0 = self.overlay(0)
        original_broadcast = node0.broadcast_block
        node0.broadcast_block = lambda height, block: None
        try:
            block = node0.mine_next_block_sync(timestamp=1)
        finally:
            node0.broadcast_block = original_broadcast
        payload = node0._payload_for_block(1, block)

        expected_hash = block_hash(
            payload.prev_hash,
            payload.txs_hash,
            payload.timestamp,
            payload.difficulty,
            payload.nonce,
        )
        self.assertEqual(payload.block_hash, expected_hash)

    async def tearDown(self):
        await super().tearDown()
