from __future__ import annotations

from blockchain_utils import Block, has_valid_pow


class Blockchain:
    def __init__(self, genesis: Block) -> None:
        self.genesis = genesis
        self.genesis_hash = genesis.header.hash()

        self.blocks: dict[bytes, Block] = {self.genesis_hash: genesis}
        self.children: dict[bytes, list[bytes]] = {self.genesis_hash: []}
        self.tip: bytes = self.genesis_hash
        self.chain_height: int = 0

    def validate_block(self, block: Block) -> bool:
        header_hash = block.header.hash()
        if not has_valid_pow(header_hash, block.header.difficulty):
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
        self.children.setdefault(parent, []).append(block_hash)
        self.children.setdefault(block_hash, [])

        if parent == self.tip:
            self.tip = block_hash
            self.chain_height += 1
            return True

        if len(self.get_chain(block_hash)) > len(self.get_chain(self.tip)):
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
        self.tip = new_tip
        self.chain_height = len(self.get_chain(new_tip)) - 1