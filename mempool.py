from __future__ import annotations

from typing import Iterable

from blockchain_utils import tx_hash

# Tx = (sender_key, data, timestamp, signature)
Tx = tuple[bytes, bytes, int, bytes]


class Mempool:
    def __init__(self) -> None:
        self.txs: dict[bytes, Tx] = {}

    def add(self, tx: Tx) -> bytes:
        txid = tx_hash(tx[0], tx[1], tx[2], tx[3])
        self.txs.setdefault(txid, tx)
        return txid

    def remove_confirmed(self, txids: Iterable[bytes]) -> None:
        for txid in txids:
            self.txs.pop(txid, None)