import unittest

from blockchain import Blockchain
from blockchain_utils import (
    Block,
    BlockHeader,
    txs_hash,
)
from mempool import Mempool

class TestBlockchain(unittest.TestCase):
    def setUp(self):
        genesis_header = BlockHeader(
            prev_hash=b"\x00" * 32,
            txs_hash=b"\x00" * 32,
            timestamp=0,
            difficulty=0,
            nonce=0,
        )
        self.genesis_block = Block(genesis_header, [])
        self.mempool = Mempool()
        self.blockchain = Blockchain(self.genesis_block, self.mempool, difficulty=0)

    def test_add_valid_block(self):
        # Difficulty 0, any hash is valid.
        header = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block = Block(header, [])
        self.assertTrue(self.blockchain.add_block(block))
        self.assertIn(block.header.hash(), self.blockchain.blocks)

    def test_add_invalid_pow_block(self):
        header = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=64,  # Essentially impossible difficulty.
            nonce=0,
        )
        block = Block(header, [])
        self.assertFalse(self.blockchain.add_block(block))
        self.assertNotIn(block.header.hash(), self.blockchain.blocks)

    def test_validate_valid_block(self):
        header = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block = Block(header, [])
        self.assertTrue(self.blockchain.validate_block(block))
    
    def test_validate_invalid_pow_block(self):
        header = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=64,  # Essentially impossible difficulty.
            nonce=0,
        )
        block = Block(header, [])
        self.assertFalse(self.blockchain.validate_block(block))

    def test_get_chain(self):
        header1 = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block1 = Block(header1, [])
        self.blockchain.add_block(block1)

        header2 = BlockHeader(
            prev_hash=block1.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=2,
            difficulty=0,
            nonce=0,
        )
        block2 = Block(header2, [])
        self.blockchain.add_block(block2)

        chain = self.blockchain.get_chain(block2.header.hash())
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[2].header.hash(), block2.header.hash())
        self.assertEqual(chain[1].header.hash(), block1.header.hash())
        self.assertEqual(chain[0].header.hash(), self.genesis_block.header.hash())

    def test_find_fork_point(self):
        header1 = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block1 = Block(header1, [])
        self.blockchain.add_block(block1)

        header2 = BlockHeader(
            prev_hash=block1.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=2,
            difficulty=0,
            nonce=0,
        )
        block2 = Block(header2, [])
        self.blockchain.add_block(block2)

        header3 = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=3,
            difficulty=0,
            nonce=0,
        )
        block3 = Block(header3, [])
        self.blockchain.add_block(block3)

        fork_point = self.blockchain.find_fork_point(block2.header.hash(), block3.header.hash())
        self.assertEqual(fork_point, self.genesis_block.header.hash())
    
    def test_find_fork_point_no_common_ancestor(self):
        header1 = BlockHeader(
            prev_hash=self.genesis_block.header.hash(),
            txs_hash=txs_hash([]),
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block1 = Block(header1, [])
        self.blockchain.add_block(block1)

        header2 = BlockHeader(
            prev_hash=b"\xFF" * 32,  # Invalid parent hash.
            txs_hash=txs_hash([]),
            timestamp=2,
            difficulty=0,
            nonce=0,
        )
        block2 = Block(header2, [])
        self.blockchain.add_block(block2)

        fork_point = self.blockchain.find_fork_point(block1.header.hash(), block2.header.hash())
        self.assertIsNone(fork_point)


if __name__ == "__main__":
    unittest.main()