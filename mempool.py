from __future__ import annotations

from typing import Iterable

from blockchain_utils import tx_hash

# Tx = (sender_key, data, timestamp, signature)
Tx = tuple[bytes, bytes, int, bytes]


class Mempool:
    def __init__(self) -> None:
        self.free_txs: dict[bytes, Tx] = {}
        self.chain_txs: dict[bytes, Tx] = {}

    def add(self, tx: Tx, remove_from_chain: bool = False) -> bytes:
        txid: bytes = tx_hash(tx[0], tx[1], tx[2], tx[3])
        if remove_from_chain:
            self.chain_txs.pop(txid, None)
        if not self.chain_txs.__contains__(txid):
            self.free_txs.setdefault(txid, tx)
        return txid

    def remove_confirmed(self, txids: Iterable[bytes]) -> None:
        for txid in txids:
            tx: Tx = self.free_txs.pop(txid, None)
            self.chain_txs.setdefault(txid, tx)