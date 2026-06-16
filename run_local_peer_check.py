from __future__ import annotations

import argparse
import asyncio
import sys
import time
import unittest
from contextlib import suppress

from ipv8.keyvault.crypto import default_eccrypto
from ipv8.test.base import TestBase

import blockchain_community
from blockchain_community import (
    BlockChainCommunitySettings,
    BlockchainCommunity,
    SubmitTransactionPayload,
)
from blockchain_utils import tx_hash, txs_hash


class LocalPeerCheck(TestBase[BlockchainCommunity]):
    args: argparse.Namespace

    async def setUp(self) -> None:
        super().setUp()
        self._saved_constants = {
            name: getattr(blockchain_community, name)
            for name in (
                "DIFFICULTY",
                "SYNC_INTERVAL",
                "SYNC_DELAY",
                "BLOCK_INTERVAL_RANGE",
                "PRUNE_INTERVAL",
            )
        }

        blockchain_community.DIFFICULTY = self.args.difficulty
        blockchain_community.SYNC_INTERVAL = 0.15
        blockchain_community.SYNC_DELAY = 0.05
        blockchain_community.BLOCK_INTERVAL_RANGE = (0.15, 0.35)
        # Keep automatic pruning out of the way; the runner triggers checkpointing explicitly.
        blockchain_community.PRUNE_INTERVAL = max(float(self.args.timeout) + 5.0, 60.0)

        self.initialize(
            overlay_class=BlockchainCommunity,
            node_count=self.args.nodes,
            settings=BlockChainCommunitySettings(
                allowed_key_hexes=set(),
                data_dir=self.temporary_directory(),
            ),
        )
        member_keys = {self.key_bin(i).hex() for i in range(self.args.nodes)}
        for i in range(self.args.nodes):
            self.overlay(i).allowed_key_hexes |= member_keys

    async def tearDown(self) -> None:
        for name, value in self._saved_constants.items():
            setattr(blockchain_community, name, value)
        await super().tearDown()

    def _heights(self) -> list[int]:
        return [self.overlay(i).blockchain.chain_height for i in range(self.args.nodes)]

    def _tips(self) -> list[bytes]:
        return [self.overlay(i).blockchain.tip for i in range(self.args.nodes)]

    def _short_tips(self) -> list[str]:
        return [tip.hex()[:10] for tip in self._tips()]

    def _tx_height(self, node: BlockchainCommunity, txid: bytes) -> int | None:
        for height, block in enumerate(node.blockchain.chain):
            if txid in block.tx_hashes:
                return height
        return None

    def _tx_known_or_on_chain(self, node: BlockchainCommunity, txid: bytes) -> bool:
        return node.mempool.is_known_tx(txid) or self._tx_height(node, txid) is not None

    def _same_chain_through(self, height: int) -> bool:
        if height < 0:
            return True
        if min(self._heights()) < height:
            return False
        for check_height in range(height + 1):
            hashes = {
                self.overlay(i).blockchain.chain[check_height].header.hash()
                for i in range(self.args.nodes)
            }
            if len(hashes) != 1:
                return False
        return True

    async def _run_until(self, label: str, predicate) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.args.timeout
        last_report = 0.0
        while loop.time() < deadline:
            await self.deliver_messages(timeout=0.25)
            if predicate():
                return
            now = loop.time()
            if now - last_report >= 2.0:
                print(f"[wait] {label}: heights={self._heights()} tips={self._short_tips()}")
                last_report = now
        raise AssertionError(
            f"timed out waiting for {label}; heights={self._heights()} tips={self._short_tips()}"
        )

    async def _cancel_task_on_all_nodes(self, task_name: str) -> None:
        for i in range(self.args.nodes):
            task = self.overlay(i).cancel_pending_task(task_name)
            with suppress(asyncio.CancelledError):
                await task

    async def test_local_peer_check(self) -> None:
        print(f"[setup] starting {self.args.nodes} mock BlockchainCommunity peers")
        await self.introduce_nodes()

        peer_counts = [len(self.overlay(i).get_peers()) for i in range(self.args.nodes)]
        print(f"[peers] counts={peer_counts}")
        self.assertTrue(
            all(count >= self.args.nodes - 1 for count in peer_counts),
            f"not all peers are connected: {peer_counts}",
        )

        for i in range(self.args.nodes):
            self.overlay(i).started()

        await self._run_until(
            f"height >= {self.args.target_height}",
            lambda: min(self._heights()) >= self.args.target_height,
        )
        print(f"[mining] heights={self._heights()} tips={self._short_tips()}")

        sender_key = self.key_bin(0)
        data = f"local-peer-check:{time.time_ns()}".encode("ascii")
        timestamp = int(time.time())
        signed_message = sender_key + data + timestamp.to_bytes(8, "big", signed=False)
        signature = default_eccrypto.create_signature(self.private_key(0), signed_message)
        txid = tx_hash(sender_key, data, timestamp, signature)

        print(f"[tx] submit {txid.hex()[:16]} from node 0 to node 1")
        self.overlay(0).ez_send(
            self.peer(1),
            SubmitTransactionPayload(sender_key, data, timestamp, signature),
        )
        await self._run_until(
            "transaction gossip",
            lambda: all(self._tx_known_or_on_chain(self.overlay(i), txid) for i in range(self.args.nodes)),
        )

        def tx_buried_everywhere() -> bool:
            heights = [self._tx_height(self.overlay(i), txid) for i in range(self.args.nodes)]
            if any(height is None for height in heights):
                return False
            if len(set(heights)) != 1:
                return False
            return all(
                self.overlay(i).blockchain.chain_height - heights[i] >= self.args.confirmations
                for i in range(self.args.nodes)
            )

        await self._run_until(
            f"transaction buried by {self.args.confirmations} blocks",
            tx_buried_everywhere,
        )
        tx_heights = [self._tx_height(self.overlay(i), txid) for i in range(self.args.nodes)]
        print(f"[tx] included_height={tx_heights[0]} all_heights={tx_heights}")

        min_height = min(self._heights())
        confirmed_height = min_height - self.args.confirmations
        self.assertGreaterEqual(confirmed_height, 0)
        self.assertTrue(self._same_chain_through(confirmed_height))
        for height in range(confirmed_height + 1):
            for i in range(self.args.nodes):
                block = self.overlay(i).blockchain.chain[height]
                self.assertEqual(txs_hash(block.tx_hashes), block.header.txs_hash)
        print(f"[chain] consistent_through_height={confirmed_height}")

        # Freeze block production so all nodes propose the same checkpoint.
        await self._cancel_task_on_all_nodes("mine")
        await self._run_until(
            "same tip after stopping miners",
            lambda: len(set(self._tips())) == 1,
        )

        checkpoint_height = self.overlay(0).blockchain.chain_height - self.args.checkpoint_depth
        self.assertGreater(checkpoint_height, 0)
        for i in range(self.args.nodes):
            self.overlay(i).blockchain.prune_depth = self.args.checkpoint_depth

        print(f"[checkpoint] proposing height={checkpoint_height}")
        for i in range(self.args.nodes):
            await self.overlay(i)._prune_step()

        quorum = max(1, (2 * self.args.nodes + 2) // 3)

        def checkpoint_applied_everywhere() -> bool:
            checkpoints = [self.overlay(i).blockchain.store.load_checkpoint() for i in range(self.args.nodes)]
            if any(checkpoint is None for checkpoint in checkpoints):
                return False
            heights = {checkpoint.height for checkpoint in checkpoints}
            hashes = {checkpoint.block_hash for checkpoint in checkpoints}
            reasons = {checkpoint.reason for checkpoint in checkpoints}
            enough_signatures = all(len(checkpoint.signatures) >= quorum for checkpoint in checkpoints)
            return (
                heights == {checkpoint_height}
                and len(hashes) == 1
                and reasons == {"quorum-finalized"}
                and enough_signatures
            )

        await self._run_until("checkpoint quorum", checkpoint_applied_everywhere)
        checkpoints = [self.overlay(i).blockchain.store.load_checkpoint() for i in range(self.args.nodes)]
        checkpoint = checkpoints[0]
        signature_counts = [len(checkpoint.signatures) for checkpoint in checkpoints]
        print(
            "[checkpoint] "
            f"height={checkpoint.height} hash={checkpoint.block_hash.hex()[:16]} "
            f"signature_counts={signature_counts}"
        )
        print("[ok] local mock peer check passed")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an offline mock-network smoke check for the Lab 3 blockchain peers."
    )
    parser.add_argument("--nodes", type=int, default=3)
    parser.add_argument("--difficulty", type=int, default=1)
    parser.add_argument("--target-height", type=int, default=6)
    parser.add_argument("--confirmations", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--checkpoint-depth", type=int, default=2)
    args = parser.parse_args(argv)

    if args.nodes < 2:
        parser.error("--nodes must be at least 2")
    if args.difficulty < 0:
        parser.error("--difficulty must be non-negative")
    if args.target_height < 1:
        parser.error("--target-height must be at least 1")
    if args.confirmations < 1:
        parser.error("--confirmations must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.checkpoint_depth < 1:
        parser.error("--checkpoint-depth must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    LocalPeerCheck.args = parse_args(sys.argv[1:] if argv is None else argv)
    suite = unittest.TestSuite([LocalPeerCheck("test_local_peer_check")])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
