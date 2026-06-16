from __future__ import annotations

from blockchain_utils import Block, has_valid_pow
from mempool import Mempool
from config import DIFFICULTY, PRUNE_DEPTH
from storage import BlockStore, unpack_header

class _BlocksView:
    # Class that behaves the same as dict, but interacts with a BlockStore.
    def __init__(self, store: BlockStore) -> None:
        self._s = store

    def __contains__(self, h: bytes) -> bool:
        return self._s.has_block(h)

    def __getitem__(self, h: bytes) -> Block:
        b = self._s.get_block(h)
        if b is None:
            raise KeyError(h)
        return b

    def get(self, h: bytes, default=None):
        b = self._s.get_block(h)
        return b if b is not None else default

    def __setitem__(self, h: bytes, block: Block) -> None:
        self._s.put_block(block)

class Blockchain:
    def __init__(self, 
                 genesis: Block, 
                 mempool: Mempool, 
                 difficulty: int = DIFFICULTY,
                 data_dir: str = "chaindata",
                 prune_depth: int = PRUNE_DEPTH) -> None:
        self.genesis = genesis
        self.genesis_hash = genesis.header.hash()
        self.difficulty = difficulty
        self.prune_depth = prune_depth
        self.mempool = mempool

        self.height_by_hash: dict[bytes, int] = {self.genesis_hash: 0}
        # self.blocks: dict[bytes, Block] = {self.genesis_hash: genesis}
        self.chain = [genesis]
        self.tip: bytes = self.genesis_hash
        self.chain_height: int = 0

        self.store = BlockStore(data_dir)
        self.blocks = _BlocksView(self.store)

        if self.store.headers.count == 0:
            self.store.put_block(genesis)
            self.store.extend(0, genesis)
        else:
            stored_genesis = self.store.headers.get(0)
            if stored_genesis is None or stored_genesis[0] != self.genesis_hash:
                raise ValueError("stored genesis does not match configured genesis")
            if self.store.get_block(self.genesis_hash) is None:
                self.store.put_block(genesis)
        self._bootstrap()

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

        if parent == self.tip:
            self.tip = block_hash
            self.chain_height += 1
            self.chain.append(block)
            self.store.extend(self.chain_height, block)
            self.mempool.remove_confirmed(block.tx_hashes)
            self._maybe_prune()
            return True

        other_height = self.height_by_hash[block_hash]
        if other_height > self.chain_height or (other_height == self.chain_height and block_hash < self.tip):
            self.reorganize(block_hash)
        return True

    # def get_chain(self, tip: bytes) -> list[Block]:
    #     chain: list[Block] = []
    #     cur = tip
    #     while True:
    #         block = self.blocks.get(cur)
    #         if block is None:
    #             return []
    #         chain.append(block)
    #         if cur == self.genesis_hash:
    #             break
    #         cur = block.header.prev_hash
    #     chain.reverse()
    #     return chain

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
        fork_height = self.height_by_hash[fork_point]
        
        cur = self.tip
        while cur != fork_point:
            cur_block = self.blocks[cur]
            for txid in cur_block.tx_hashes:
                self.mempool.move_from_chain(txid)
            cur = cur_block.header.prev_hash

        suffix: list[Block] = []
        cur = new_tip
        while cur != fork_point:
            cur_block = self.blocks[cur]
            self.mempool.remove_confirmed(cur_block.tx_hashes)
            suffix.append(cur_block)
            cur = cur_block.header.prev_hash
        suffix.reverse()

        self.tip = new_tip
        self.chain = self.chain[: fork_height + 1] + suffix
        self.chain_height = fork_height + len(suffix)
        
        self.store.reorg_to(fork_height)
        for height in range(fork_height + 1, self.chain_height + 1):
            self.store.extend(height, self.chain[height])
        self._maybe_prune()

    def _bootstrap(self) -> None:
        for height in range(1, self.store.headers.count):
            block_hash, header = self.store.headers.get(height)
            block = self.store.get_block(block_hash)
            if block is None:
                block = Block(header=unpack_header(header), tx_hashes=[])
            self.height_by_hash[block_hash] = height
            self.chain.append(block)
            self.tip = block_hash
            self.chain_height = height
    
    def _maybe_prune(self) -> None:
        floor = self.chain_height - self.prune_depth
        if floor <= 0:
            return
        keep = {block_hash for block_hash, height in self.height_by_hash.items() if height >= floor}
        keep.add(self.genesis_hash)
        self.store.prune(keep=lambda k: k in keep)
        for block_hash, height in list(self.height_by_hash.items()):
            if height < floor and block_hash != self.genesis_hash:
                self.height_by_hash.pop(block_hash, None)
