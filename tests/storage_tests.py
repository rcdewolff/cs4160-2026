import os
import tempfile
import unittest

from blockchain_utils import BlockHeader, HASH_SIZE, txs_hash
from storage import BlockStore, HDR_REC, HeaderLog, LogStore


def make_header(prev_hash: bytes, timestamp: int) -> BlockHeader:
    return BlockHeader(
        prev_hash=prev_hash,
        txs_hash=txs_hash([]),
        timestamp=timestamp,
        difficulty=0,
        nonce=0,
    )


class StorageRecoveryTests(unittest.TestCase):
    def test_header_log_recovers_and_truncates_torn_tail(self):
        with tempfile.TemporaryDirectory() as data_dir:
            path = os.path.join(data_dir, "headers.log")
            genesis = make_header(b"\x00" * HASH_SIZE, 0)
            block1 = make_header(genesis.hash(), 1)

            log = HeaderLog(path)
            log.append(0, genesis.hash(), genesis.pack())
            log.append(1, block1.hash(), block1.pack())
            log.close()

            with open(path, "ab") as f:
                f.write(b"torn-record")

            recovered = HeaderLog(path)

            self.assertEqual(recovered.count, 2)
            self.assertEqual(os.path.getsize(path), 2 * HDR_REC)
            self.assertEqual(recovered.get(1)[0], block1.hash())
            recovered.close()

    def test_log_store_recovers_and_truncates_torn_tail(self):
        with tempfile.TemporaryDirectory() as data_dir:
            store = LogStore(data_dir)
            store.put(b"key", b"value")
            segment_path = store._seg_path(store.active)
            store.close()

            with open(segment_path, "ab") as f:
                f.write(b"\x00\x00\x00\xffpartial")

            recovered = LogStore(data_dir)

            self.assertEqual(recovered.get(b"key"), b"value")
            self.assertIsNone(recovered.get(b"missing"))
            recovered.close()

    def test_checkpoint_round_trips_through_store(self):
        with tempfile.TemporaryDirectory() as data_dir:
            block_hash = b"\x22" * HASH_SIZE

            store = BlockStore(data_dir)
            written = store.write_checkpoint(5, block_hash, signatures=("a", "b"))
            store.close()

            recovered = BlockStore(data_dir)
            loaded = recovered.load_checkpoint()

            self.assertEqual(loaded.height, 5)
            self.assertEqual(loaded.block_hash, block_hash)
            self.assertEqual(loaded.signatures, ("a", "b"))
            self.assertEqual(loaded.reason, written.reason)
            recovered.close()


if __name__ == "__main__":
    unittest.main()
