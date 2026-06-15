from __future__ import annotations

from blockchain_utils import Block, has_valid_pow
from mempool import Mempool
from config import DIFFICULTY


class Blockchain:
    def __init__(self, genesis: Block, mempool: Mempool, difficulty: int = DIFFICULTY) -> None:
        self.genesis = genesis
        self.genesis_hash = genesis.header.hash()
        self.difficulty = difficulty

        self.mempool = mempool

        self.height_by_hash: dict[bytes, int] = {self.genesis_hash: 0}
        self.blocks: dict[bytes, Block] = {self.genesis_hash: genesis}
        self.children: dict[bytes, list[bytes]] = {self.genesis_hash: []}
        self.chain = [genesis]
        self.tip: bytes = self.genesis_hash
        self.chain_height: int = 0

    def validate_block(self, block: Block) -> bool:
        header_hash = block.header.hash()
        if block.header.difficulty < self.difficulty or not has_valid_pow(header_hash, self.difficulty) or not has_valid_pow(header_hash, block.header.difficulty):
            print(f"Invalid PoW for block with hash {header_hash.hex()}")
            return False
        if not block.is_body_hash_valid():
            print(f"Invalid body hash for block with hash {header_hash.hex()}")
            return False
        return True

    def add_block(self, block: Block) -> bool:
        if not self.validate_block(block):
            return False

        block_hash = block.header.hash()
        if block_hash in self.blocks:
            return False

        parent = block.header.prev_hash
        if parent not in self.blocks:
            return False

        self.blocks[block_hash] = block
        self.height_by_hash[block_hash] = self.height_by_hash[parent] + 1
        self.children.setdefault(parent, []).append(block_hash)
        self.children.setdefault(block_hash, [])

        if parent == self.tip:
            self.tip = block_hash
            self.chain_height += 1
            self.chain.append(block)
            self.mempool.remove_confirmed(block.tx_hashes)
            return True

        # print(f"Found new block elsewhere: {block.header.hash().hex()}")

        other_height = self.height_by_hash[block_hash]
        if other_height > self.chain_height or (other_height == self.chain_height and block_hash < self.tip):
            self.reorganize(block_hash)
        return True

    def get_chain(self, tip: bytes) -> list[Block]:
        chain: list[Block] = []
        cur = tip
        while True:
            block = self.blocks.get(cur)
            if block is None:
                return []
            chain.append(block)
            if cur == self.genesis_hash:
                break
            cur = block.header.prev_hash
        chain.reverse()
        return chain

    def find_fork_point(self, hash_a: bytes, hash_b: bytes) -> bytes | None:
        seen: set[bytes] = set()
        cur = hash_a
        while cur in self.blocks:
            seen.add(cur)
            if cur == self.genesis_hash:
                break
            cur = self.blocks[cur].header.prev_hash

        cur = hash_b
        while cur in self.blocks:
            if cur in seen:
                return cur
            if cur == self.genesis_hash:
                break
            cur = self.blocks[cur].header.prev_hash
        return None

    def reorganize(self, new_tip: bytes) -> None:
        fork_point = self.find_fork_point(self.tip, new_tip)
        if fork_point is None:
            fork_point = self.genesis_hash
        
        cur = self.tip
        while cur != fork_point:
            cur_block = self.blocks[cur]
            for txid in cur_block.tx_hashes:
                self.mempool.move_from_chain(txid)
            cur = cur_block.header.prev_hash

        cur = new_tip
        while cur != fork_point:
            cur_block = self.blocks[cur]
            self.mempool.remove_confirmed(cur_block.tx_hashes)
            cur = cur_block.header.prev_hash

        self.tip = new_tip
        self.chain_height = len(self.get_chain(new_tip)) - 1
        self.chain = self.get_chain(self.tip)