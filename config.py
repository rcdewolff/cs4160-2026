# Proof-of-work difficulty (leading zero bits) every node mines at. All three nodes MUST share
# this value, the genesis layout, and the community_id, or the longest-chain rule disagrees.
DIFFICULTY = 22
# Nonces tried per synchronous burst before yielding to the event loop. Keeps the CPU-bound miner
# from starving IPv8's UDP receive and the sync loop.
MINE_CHUNK = 20000
# Target time between a node's own blocks (randomized). MUST stay comfortably above block
# propagation latency (~one sync round trip) so the three chains rarely fork.
BLOCK_INTERVAL_RANGE = (1.5, 2.5)
# How often a node polls teammates for their height/tip (safety net; mining also pushes its tip).
SYNC_INTERVAL = 0.5
SYNC_DELAY = 1.0
# When catching up, also refetch a few blocks below our tip so shallow reorgs can find a common
# ancestor, and cap how many blocks we request per peer per tick.
SYNC_DOWN_WINDOW = 16
FETCH_BATCH = 64
# Upper bound on buffered out-of-order (orphan) blocks.
PENDING_CAP = 1000
