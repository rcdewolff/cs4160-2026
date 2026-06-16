import unittest
import tempfile
import shutil
from uuid import uuid1

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
        self.data_dir = f"TestBlockchain_temp_{uuid1()}"
        self.blockchain = Blockchain(self.genesis_block, self.mempool, difficulty=0, data_dir=self.data_dir)

    def tearDown(self):
        self.blockchain.store.close()
        shutil.rmtree(self.data_dir, ignore_errors=True)

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

        chain = self.blockchain.chain
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

    def test_bootstrap_restores_persisted_chain(self):
        with tempfile.TemporaryDirectory() as data_dir:
            mempool = Mempool()
            blockchain = Blockchain(self.genesis_block, mempool, difficulty=0, data_dir=data_dir)

            header1 = BlockHeader(
                prev_hash=self.genesis_block.header.hash(),
                txs_hash=txs_hash([]),
                timestamp=1,
                difficulty=0,
                nonce=0,
            )
            block1 = Block(header1, [])
            blockchain.add_block(block1)

            header2 = BlockHeader(
                prev_hash=block1.header.hash(),
                txs_hash=txs_hash([]),
                timestamp=2,
                difficulty=0,
                nonce=0,
            )
            block2 = Block(header2, [])
            blockchain.add_block(block2)
            blockchain.store.close()

            restored = Blockchain(self.genesis_block, Mempool(), difficulty=0, data_dir=data_dir)

            self.assertEqual(restored.chain_height, 2)
            self.assertEqual(restored.tip, block2.header.hash())
            self.assertEqual(len(restored.chain), 3)
            self.assertEqual(restored.chain[2].header.hash(), block2.header.hash())
            restored.store.close()

    def test_reorg_persists_tip_header(self):
        with tempfile.TemporaryDirectory() as data_dir:
            blockchain = Blockchain(self.genesis_block, Mempool(), difficulty=0, data_dir=data_dir)
            genesis = blockchain.tip

            a1 = Block(BlockHeader(genesis, txs_hash([]), 1, 0, 0), [])
            b1 = Block(BlockHeader(genesis, txs_hash([]), 2, 0, 0), [])
            b2 = Block(BlockHeader(b1.header.hash(), txs_hash([]), 3, 0, 0), [])

            blockchain.add_block(a1)
            blockchain.add_block(b1)
            blockchain.add_block(b2)

            self.assertEqual(blockchain.store.headers.count, blockchain.chain_height + 1)
            stored_tip = blockchain.store.get_block_by_height(blockchain.chain_height)
            self.assertIsNotNone(stored_tip)
            self.assertEqual(stored_tip.header.hash(), blockchain.tip)
            blockchain.store.close()

    def test_prune_keeps_genesis_body_available(self):
        with tempfile.TemporaryDirectory() as data_dir:
            blockchain = Blockchain(self.genesis_block, Mempool(), difficulty=0, data_dir=data_dir, prune_depth=1)
            prev = blockchain.tip
            for timestamp in range(1, 4):
                block = Block(BlockHeader(prev, txs_hash([]), timestamp, 0, 0), [])
                blockchain.add_block(block)
                prev = block.header.hash()
            blockchain.prune_once()

            self.assertIsNotNone(blockchain.store.get_block(blockchain.genesis_hash))
            self.assertIn(blockchain.genesis_hash, blockchain.blocks)
            blockchain.store.close()


if __name__ == "__main__":
    unittest.main()
