from __future__ import annotations

import json
import os
import struct
import tempfile
import threading
import zlib
from typing import Callable, Optional

from blockchain_utils import (
    Block,
    BlockHeader,
    HASH_SIZE,
    HEADER_SIZE,
    hash_block_header,
    split_tx_hashes,
)

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _fsync_dir(path: str) -> None:
    """Best-effort: make a rename inside `path` durable by fsyncing the
    directory. POSIX needs this; platforms without a directory fd (Windows)
    skip it. Rename atomicity — which is what prevents corruption — holds
    regardless."""
    flags = getattr(os, "O_DIRECTORY", os.O_RDONLY)
    try:
        fd = os.open(path, flags)
    except OSError:
        return   
    try:
        os.fsync(fd)
    except OSError:
        pass  
    finally:
        os.close(fd)


def _open_rw(path: str):
    """Open for read+write, creating the file if it does not exist."""
    if not os.path.exists(path):
        open(path, "wb").close()
    return open(path, "r+b")


def unpack_header(b: bytes) -> BlockHeader:
    prev, txs, ts, diff, nonce = struct.unpack(">32s32sQIQ", b)
    return BlockHeader(prev, txs, ts, diff, nonce)


# ---------------------------------------------------------------------------
# HeaderLog: the verifiable backbone and the crash-commit point.
#
# Fixed-size records => random access by height is a single seek (O(1)), and a
# torn write is trivially detectable (file length not a multiple of the record
# size, or a record whose CRC / hash / prev-link does not check out). Headers
# are 84 bytes, so this file is tiny (~128 B/block) and is NEVER pruned: it is
# what keeps the whole chain verifiable after bodies are dropped.
# ---------------------------------------------------------------------------

# crc(4) | height(8) | block_hash(32) | header(84)
HDR_REC = 4 + 8 + HASH_SIZE + HEADER_SIZE  # = 128
_ZERO = b"\x00" * HASH_SIZE


class HeaderLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self.count = 0  # number of valid records == chain_height + 1
        self._f = _open_rw(path)
        self._recover()

    def _recover(self) -> None:
        self._f.seek(0, os.SEEK_END)
        size = self._f.tell()
        n = size // HDR_REC
        valid = 0
        prev_hash = _ZERO
        self._f.seek(0)
        for i in range(n):
            rec = self._f.read(HDR_REC)
            if len(rec) != HDR_REC:
                break
            (crc,) = struct.unpack(">I", rec[:4])
            body = rec[4:]
            if (zlib.crc32(body) & 0xFFFFFFFF) != crc:
                break  # torn / corrupt record
            (height,) = struct.unpack(">Q", body[:8])
            bhash = body[8 : 8 + HASH_SIZE]
            hdr = body[8 + HASH_SIZE :]
            if height != i or hash_block_header(hdr) != bhash:
                break
            if i != 0 and hdr[:HASH_SIZE] != prev_hash:
                break  # broken parent linkage
            prev_hash = bhash
            valid += 1
        good = valid * HDR_REC
        if good != size:
            self._f.truncate(good)  # drop the torn tail
            self._f.flush()
            os.fsync(self._f.fileno())
        self.count = valid

    def append(self, height: int, block_hash: bytes, header_bytes: bytes) -> None:
        assert height == self.count, (height, self.count)
        body = struct.pack(">Q", height) + block_hash + header_bytes
        crc = zlib.crc32(body) & 0xFFFFFFFF
        self._f.seek(self.count * HDR_REC)
        self._f.write(struct.pack(">I", crc) + body)
        self._f.flush()
        os.fsync(self._f.fileno())
        self.count += 1

    def truncate_to(self, height: int) -> None:
        """Keep records [0, height]; drop the rest. Used on a reorg."""
        self._f.truncate((height + 1) * HDR_REC)
        self._f.flush()
        os.fsync(self._f.fileno())
        self.count = height + 1

    def get(self, height: int) -> Optional[tuple[bytes, bytes]]:
        if not (0 <= height < self.count):
            return None
        self._f.seek(height * HDR_REC)
        body = self._f.read(HDR_REC)[4:]
        return body[8 : 8 + HASH_SIZE], body[8 + HASH_SIZE :]  # (block_hash, header_bytes)

    def close(self) -> None:
        self._f.close()


# ---------------------------------------------------------------------------
# LogStore: append-only, segmented key/value store.
#
#   * O(1) reads     -> in-memory keydir {key: (segment_id, offset)}
#   * append fast    -> one append + fsync to the single active segment
#   * crash safe     -> per-record CRC; a torn tail fails the check and is
#                       truncated on recovery; the keydir is only a hint and is
#                       always rebuilt from the segments
#   * compact / prune in the background, without blocking writes -> compaction
#                       only reads SEALED segments and writes a brand new one,
#                       never touching the active segment that appends go to.
#                       The single atomic switch is the CURRENT manifest
#                       (temp file + rename).
# ---------------------------------------------------------------------------

# crc(4) | klen(4) | vlen(4) | key | value     (crc covers everything after it)
_HEAD = struct.Struct(">III")
SEG_PREFIX, SEG_SUFFIX = "seg-", ".log"


class LogStore:
    def __init__(self, dir_path: str, max_seg_bytes: int = 8 * 1024 * 1024) -> None:
        self.dir = dir_path
        self.max_seg_bytes = max_seg_bytes
        self.index: dict[bytes, tuple[int, int]] = {}
        self.lock = threading.Lock()
        os.makedirs(dir_path, exist_ok=True)
        self._load_manifest()
        self._rebuild_index()
        self._open_active()

    # ---- manifest (the atomic commit point) -------------------------------

    def _manifest_path(self) -> str:
        return os.path.join(self.dir, "CURRENT")

    def _seg_path(self, sid: int) -> str:
        return os.path.join(self.dir, f"{SEG_PREFIX}{sid:06d}{SEG_SUFFIX}")

    def _load_manifest(self) -> None:
        p = self._manifest_path()
        if os.path.exists(p):
            with open(p) as f:
                m = json.load(f)
            self.segments = list(m["segments"])
            self.active = m["active"]
        else:
            self.segments = [0]
            self.active = 0
            self._write_manifest()
        # Any segment file not referenced by CURRENT is stale (a half-finished
        # compaction or a superseded input) and is safe to delete.
        for name in os.listdir(self.dir):
            if name.startswith(SEG_PREFIX) and name.endswith(SEG_SUFFIX):
                sid = int(name[len(SEG_PREFIX) : -len(SEG_SUFFIX)])
                if sid not in self.segments:
                    os.remove(os.path.join(self.dir, name))

    def _write_manifest(self) -> None:
        m = {"segments": self.segments, "active": self.active}
        fd, tmp = tempfile.mkstemp(dir=self.dir)
        with os.fdopen(fd, "w") as f:
            json.dump(m, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._manifest_path())  # atomic
        _fsync_dir(self.dir)

    # ---- recovery ---------------------------------------------------------

    def _scan_segment(self, sid: int) -> list[tuple[bytes, bytes, int]]:
        """Return [(key, value, offset)] and truncate a torn tail if present."""
        path = self._seg_path(sid)
        if not os.path.exists(path):
            open(path, "wb").close()
            return []
        with open(path, "rb") as f:
            data = f.read()
        out, i, n = [], 0, len(data)
        while i + 12 <= n:
            crc, klen, vlen = _HEAD.unpack(data[i : i + 12])
            end = i + 12 + klen + vlen
            if end > n:
                break
            payload = data[i + 4 : end]
            if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
                break
            out.append((data[i + 12 : i + 12 + klen], data[i + 12 + klen : end], i))
            i = end
        if i != n:  # torn tail
            with open(path, "r+b") as f:
                f.truncate(i)
        return out

    def _rebuild_index(self) -> None:
        self.index = {}
        for sid in self.segments:
            for key, _val, off in self._scan_segment(sid):
                self.index[key] = (sid, off)

    def _open_active(self) -> None:
        self._af = _open_rw(self._seg_path(self.active))
        self._af.seek(0, os.SEEK_END)
        self._aoff = self._af.tell()

    # ---- writes -----------------------------------------------------------

    def put(self, key: bytes, value: bytes) -> None:
        with self.lock:
            if key in self.index:  # immutable content, dedup by key
                return
            body = struct.pack(">II", len(key), len(value)) + key + value
            crc = zlib.crc32(body) & 0xFFFFFFFF
            rec = struct.pack(">I", crc) + body
            self._af.seek(self._aoff)
            self._af.write(rec)
            self._af.flush()
            os.fsync(self._af.fileno())
            self.index[key] = (self.active, self._aoff)
            self._aoff += len(rec)
            if self._aoff >= self.max_seg_bytes:
                self._roll_locked()

    def _roll_locked(self) -> None:
        self._af.close()
        new_id = max(self.segments) + 1
        self.segments.append(new_id)
        self.active = new_id
        self._write_manifest()
        self._open_active()

    def roll(self) -> None:
        with self.lock:
            self._roll_locked()

    # ---- reads ------------------------------------------------------------

    def get(self, key: bytes) -> Optional[bytes]:
        with self.lock:
            loc = self.index.get(key)
        if loc is None:
            return None
        sid, off = loc
        with open(self._seg_path(sid), "rb") as f:
            f.seek(off)
            head = f.read(12)
            crc, klen, vlen = _HEAD.unpack(head)
            rest = f.read(klen + vlen)
        if (zlib.crc32(head[4:] + rest) & 0xFFFFFFFF) != crc:
            return None
        return rest[klen : klen + vlen]

    def __contains__(self, key: bytes) -> bool:
        with self.lock:
            return key in self.index

    # ---- compaction / pruning --------------------------------------------

    def compact(self, keep: Callable[[bytes], bool], on_chunk: Optional[Callable] = None,
                chunk: int = 1000) -> int:
        """Rewrite every SEALED segment into one fresh segment, keeping only keys
        for which keep(key) is True. Returns the number of records dropped.

        Safe to run on a background thread/task: it never writes the active
        segment, so appends proceed concurrently. `on_chunk` is called every
        `chunk` records so a cooperative scheduler can yield."""
        sealed = [s for s in self.segments if s != self.active]
        if not sealed:
            return 0

        new_id = max(self.segments) + 1
        new_path = self._seg_path(new_id)
        moved: dict[bytes, tuple[int, int]] = {}
        dropped = 0
        with open(new_path, "wb") as out:
            off = written = 0
            for sid in sealed:
                for key, val, _ in self._scan_segment(sid):
                    if not keep(key):
                        dropped += 1
                        continue
                    body = struct.pack(">II", len(key), len(val)) + key + val
                    rec = struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF) + body
                    out.write(rec)
                    moved[key] = (new_id, off)
                    off += len(rec)
                    written += 1
                    if on_chunk and written % chunk == 0:
                        on_chunk()
            out.flush()
            os.fsync(out.fileno())

        # Commit: flip CURRENT atomically, then repoint the in-memory index.
        with self.lock:
            self.segments = [new_id, self.active]
            self._write_manifest()  # <-- the single durable, atomic switch
            for key in list(self.index.keys()):
                if self.index[key][0] in sealed:
                    if key in moved:
                        self.index[key] = moved[key]
                    else:
                        del self.index[key]  # pruned away

        for sid in sealed:  # post-commit cleanup; stale files anyway after the swap
            try:
                os.remove(self._seg_path(sid))
            except FileNotFoundError:
                pass
        return dropped

    def disk_bytes(self) -> int:
        total = 0
        for sid in self.segments:
            p = self._seg_path(sid)
            if os.path.exists(p):
                total += os.path.getsize(p)
        return total

    def close(self) -> None:
        self._af.close()


# ---------------------------------------------------------------------------
# BlockStore: the facade the Blockchain talks to. Headers = verifiable backbone
# (never pruned), bodies = prunable LogStore keyed by block hash.
# ---------------------------------------------------------------------------

class BlockStore:
    def __init__(self, base_dir: str) -> None:
        os.makedirs(base_dir, exist_ok=True)
        self.headers = HeaderLog(os.path.join(base_dir, "headers.log"))
        self.bodies = LogStore(os.path.join(base_dir, "bodies"))

    # body store (keyed by block hash) -------------------------------------
    def put_block(self, block: Block) -> None:
        key = block.header.hash()
        value = block.header.pack() + b"".join(block.tx_hashes)
        self.bodies.put(key, value)

    def get_block(self, block_hash: bytes) -> Optional[Block]:
        v = self.bodies.get(block_hash)
        if v is None:
            return None
        return Block(header=unpack_header(v[:HEADER_SIZE]),
                     tx_hashes=split_tx_hashes(v[HEADER_SIZE:]))

    def has_block(self, block_hash: bytes) -> bool:
        return block_hash in self.bodies

    # main-chain headers (the commit point) --------------------------------
    def extend(self, height: int, block: Block) -> None:
        self.headers.append(height, block.header.hash(), block.header.pack())

    def reorg_to(self, fork_height: int) -> None:
        self.headers.truncate_to(fork_height)

    def header_height(self) -> int:
        return self.headers.count - 1

    def get_block_by_height(self, height: int) -> Optional[Block]:
        h = self.headers.get(height)
        if h is None:
            return None
        return self.get_block(h[0])  # None if the body was pruned

    # prune + reclaim ------------------------------------------------------
    def prune(self, keep: Callable[[bytes], bool], **kw) -> int:
        self.bodies.roll()  # seal current data so it becomes eligible
        return self.bodies.compact(keep, **kw)

    def close(self) -> None:
        self.headers.close()
        self.bodies.close()
