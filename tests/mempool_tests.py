import unittest

from mempool import Mempool

class TestMempool(unittest.TestCase):
    def setUp(self):
        self.mempool = Mempool()
    
    def test_add_and_remove_tx(self):
        tx1 = (b"sender1", b"data1", 1780489462345, b"signature1")
        tx2 = (b"sender2", b"data2", 1780489462346, b"signature2")

        txid1, _ = self.mempool.add(tx1)
        txid2, _ = self.mempool.add(tx2)

        self.assertIn(txid1, self.mempool.free_txs)
        self.assertIn(txid2, self.mempool.free_txs)

        self.mempool.remove_confirmed([txid1])
        self.assertNotIn(txid1, self.mempool.free_txs)
        self.assertIn(txid2, self.mempool.free_txs)


if __name__ == "__main__":
    unittest.main()