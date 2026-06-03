from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8

from blockchain_community import (
  BlockChainCommunitySettings,
  BlockchainCommunity,
)
from blockchain_utils import HASH_SIZE, BlockHeader, txs_hash

DUMMY_ALLOWED_KEY_HEXES = ["a" * 148, "b" * 148, "c" * 148, "d" * 148]

class BlockchainCommunityTests(TestBase[BlockchainCommunity]):
    def setUp(self):
        super().setUp()
        self.initialize(overlay_class=BlockchainCommunity,
                        node_count=4,
                        settings=BlockChainCommunitySettings(allowed_key_hexes=set(DUMMY_ALLOWED_KEY_HEXES)),)

    def test_community_initialization(self):
        allowed_keys = self.overlay(0).allowed_key_hexes
        self.assertEqual(allowed_keys, set(DUMMY_ALLOWED_KEY_HEXES))
        first_block = BlockHeader(
          prev_hash=b"\x00" * HASH_SIZE,
          txs_hash=txs_hash([]),
          timestamp=0,
          difficulty=0,
          nonce=0,
        )
        self.assertEqual(len(self.overlay(0).blockchain.get_chain(self.overlay(0).blockchain.tip)), 1)
        self.assertEqual(self.overlay(0).blockchain.get_chain(self.overlay(0).blockchain.tip)[0].header, first_block)

    async def tearDown(self):
        await super().tearDown()