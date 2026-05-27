import hashlib
import struct
import unittest

from blockchain_utils import (
    HASH_SIZE,
    HEADER_SIZE,
    Block,
    BlockHeader,
    block_hash,
    hash_block_header,
    has_valid_pow,
    leading_zero_bits,
    mine_nonce,
    pack_block_header,
    split_tx_hashes,
    tx_hash,
    txs_hash,
)


class TestBlockchainUtils(unittest.TestCase):
    def test_pack_block_header_layout(self):
        prev_hash = b"\x01" * HASH_SIZE
        txs_hash_value = b"\x02" * HASH_SIZE
        timestamp = 0x0102030405060708
        difficulty = 0x01020304
        nonce = 0x0A0B0C0D0E0F1011

        header = pack_block_header(prev_hash, txs_hash_value, timestamp, difficulty, nonce)
        self.assertEqual(len(header), HEADER_SIZE)

        unpacked = struct.unpack(">32s32sQIQ", header)
        self.assertEqual(unpacked[0], prev_hash)
        self.assertEqual(unpacked[1], txs_hash_value)
        self.assertEqual(unpacked[2], timestamp)
        self.assertEqual(unpacked[3], difficulty)
        self.assertEqual(unpacked[4], nonce)

    def test_hash_block_header_matches_sha256(self):
        header = b"A" * HEADER_SIZE
        expected = hashlib.sha256(header).digest()
        self.assertEqual(hash_block_header(header), expected)

    def test_block_hash_matches_header_hash(self):
        prev_hash = b"\x00" * HASH_SIZE
        txs_hash_value = b"\xFF" * HASH_SIZE
        timestamp = 42
        difficulty = 1
        nonce = 7

        header = pack_block_header(prev_hash, txs_hash_value, timestamp, difficulty, nonce)
        self.assertEqual(block_hash(prev_hash, txs_hash_value, timestamp, difficulty, nonce),
                         hashlib.sha256(header).digest())

    def test_tx_hash_formula(self):
        sender_key = b"sender"
        data = b"payload"
        timestamp = 1
        signature = b"sig"
        timestamp_be = timestamp.to_bytes(8, "big", signed=False)
        expected = hashlib.sha256(sender_key + data + timestamp_be + signature).digest()
        self.assertEqual(tx_hash(sender_key, data, timestamp, signature), expected)

    def test_txs_hash_empty_and_non_empty(self):
        self.assertEqual(txs_hash([]), hashlib.sha256(b"").digest())

        h1 = hashlib.sha256(b"a").digest()
        h2 = hashlib.sha256(b"b").digest()
        expected = hashlib.sha256(h1 + h2).digest()
        self.assertEqual(txs_hash([h1, h2]), expected)

    def test_split_tx_hashes(self):
        h1 = b"\x11" * HASH_SIZE
        h2 = b"\x22" * HASH_SIZE
        blob = h1 + h2
        self.assertEqual(split_tx_hashes(blob), [h1, h2])
        with self.assertRaises(ValueError):
            split_tx_hashes(blob + b"\x00")

    def test_leading_zero_bits(self):
        digest = b"\x00\x00\x10" + (b"\xFF" * 29)
        self.assertEqual(leading_zero_bits(digest), 19)
        self.assertEqual(leading_zero_bits(b"\x00" * HASH_SIZE), 256)

    def test_has_valid_pow(self):
        digest = b"\x00\x00\x10" + (b"\xFF" * 29)
        self.assertTrue(has_valid_pow(digest, 19))
        self.assertFalse(has_valid_pow(digest, 20))
        with self.assertRaises(ValueError):
            has_valid_pow(digest, -1)

    def test_mine_nonce_success_and_failure(self):
        prev_hash = b"\x00" * HASH_SIZE
        txs_hash_value = b"\x01" * HASH_SIZE
        timestamp = 123
        difficulty = 0
        start_nonce = 9

        nonce, digest = mine_nonce(
            prev_hash,
            txs_hash_value,
            timestamp,
            difficulty,
            start_nonce=start_nonce,
            max_attempts=1,
        )
        self.assertEqual(nonce, start_nonce)
        self.assertEqual(
            digest,
            block_hash(prev_hash, txs_hash_value, timestamp, difficulty, start_nonce),
        )

        with self.assertRaises(RuntimeError):
            mine_nonce(
                prev_hash,
                txs_hash_value,
                timestamp,
                257,
                start_nonce=0,
                max_attempts=1,
            )

    def test_block_header_and_block(self):
        tx_hashes = [hashlib.sha256(b"x").digest(), hashlib.sha256(b"y").digest()]
        txs_hash_value = txs_hash(tx_hashes)

        header = BlockHeader(
            prev_hash=b"\x00" * HASH_SIZE,
            txs_hash=txs_hash_value,
            timestamp=1,
            difficulty=0,
            nonce=0,
        )
        block = Block(header=header, tx_hashes=tx_hashes)
        self.assertTrue(block.is_body_hash_valid())

        bad_header = BlockHeader(
            prev_hash=header.prev_hash,
            txs_hash=b"\xFF" * HASH_SIZE,
            timestamp=header.timestamp,
            difficulty=header.difficulty,
            nonce=header.nonce,
        )
        bad_block = Block(header=bad_header, tx_hashes=tx_hashes)
        self.assertFalse(bad_block.is_body_hash_valid())


if __name__ == "__main__":
    unittest.main()