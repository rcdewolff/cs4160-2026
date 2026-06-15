from __future__ import annotations

from typing import Iterable
import copy

from blockchain_utils import tx_hash

# Tx = (sender_key, data, timestamp, signature)
Tx = tuple[bytes, bytes, int, bytes]


class Mempool:
    def __init__(self) -> None:
        self.free_txs: dict[bytes, Tx] = {}
        self.chain_txs: dict[bytes, Tx] = {}
        self.tx_order: list[bytes] = []

    def is_known_tx(self, txid: bytes) -> bool:
        return txid in self.free_txs or txid in self.chain_txs

    def add(self, tx: Tx, remove_from_chain: bool = False) -> tuple[bytes, bool]:
        txid: bytes = tx_hash(tx[0], tx[1], tx[2], tx[3])
        is_new = not self.is_known_tx(txid)
        if is_new:
            self.tx_order.append(txid)
        if remove_from_chain:
            self.chain_txs.pop(txid, None)
        if txid not in self.chain_txs:
            self.free_txs.setdefault(txid, tx)
        return txid, is_new
    
    def move_from_chain(self, txid: bytes) -> bool:
        tx = self.chain_txs.pop(txid, None)
        if tx is None:
            return False
        self.add(tx)
        return True

    def remove_confirmed(self, txids: Iterable[bytes]) -> None:
        txids = copy.deepcopy(txids)
        for txid in txids:
            tx: Tx = self.free_txs.pop(txid, None)
            if tx is not None:
                self.chain_txs.setdefault(txid, tx)
