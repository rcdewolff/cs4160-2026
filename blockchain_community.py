import os

from ipv8.community import Community, CommunitySettings
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from blockchain import Blockchain
from blockchain_utils import (
	Block,
	BlockHeader,
	HASH_SIZE,
	block_hash,
	has_valid_pow,
	split_tx_hashes,
	tx_hash,
	txs_hash,
)
from mempool import Mempool


DEFAULT_SERVER_PUBLIC_KEY_HEX = (
	"4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4"
	"350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f"
	"791324495e083331ce6"
)
PUBLIC_KEY = os.environ.get("PUB_KEY", None)
PUBLIC_KEY_MEMBER1 = os.environ.get("PUB_KEY_MEMBER1", None)
PUBLIC_KEY_MEMBER2 = os.environ.get("PUB_KEY_MEMBER2", None)

ALLOWED_KEY_HEXES = [PUBLIC_KEY, PUBLIC_KEY_MEMBER1, PUBLIC_KEY_MEMBER2, DEFAULT_SERVER_PUBLIC_KEY_HEX]


# Blockchain community payloads.
@vp_compile
class SubmitTransactionPayload(VariablePayload):
	msg_id = 1

	format_list = ["varlenH", "varlenH", "q", "varlenH"]
	names = ["sender_key", "data", "timestamp", "signature"]


@vp_compile
class SubmitTransactionResponsePayload(VariablePayload):
	msg_id = 2

	format_list = ["?", "varlenH", "varlenHutf8"]
	names = ["success", "tx_hash", "message"]


@vp_compile
class GetChainHeightPayload(VariablePayload):
	msg_id = 3

	format_list = ["q"]
	names = ["request_id"]


@vp_compile
class ChainHeightResponsePayload(VariablePayload):
	msg_id = 4

	format_list = ["q", "q", "varlenH"]
	names = ["request_id", "height", "tip_hash"]


@vp_compile
class GetBlockPayload(VariablePayload):
	msg_id = 5

	format_list = ["q"]
	names = ["height"]


@vp_compile
class BlockResponsePayload(VariablePayload):
	msg_id = 6

	format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
	names = [
		"height",
		"prev_hash",
		"txs_hash",
		"timestamp",
		"difficulty",
		"nonce",
		"block_hash",
		"tx_hashes",
	]

class BlockChainCommunitySettings(CommunitySettings):
	allowed_key_hexes: set[str]

class BlockchainCommunity(Community):
	community_id = bytes(20)
	settings_class = BlockChainCommunitySettings

	def __init__(self, settings):
		super().__init__(settings)

		self.crypto = default_eccrypto
		self.allowed_key_hexes = set(settings.allowed_key_hexes) or set(ALLOWED_KEY_HEXES)

		self.mempool = Mempool()
		self.blockchain = Blockchain(self._init_genesis(), self.mempool)
		self.peer_heights = {}

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)

	def _is_approved_peer(self, peer: Peer) -> bool:
		return peer.public_key.key_to_bin().hex() in self.allowed_key_hexes

	def _init_genesis(self) -> Block:
		genesis_txs_hash = txs_hash([])
		genesis_header = BlockHeader(
			prev_hash=b"\x00" * HASH_SIZE,
			txs_hash=genesis_txs_hash,
			timestamp=0,
			difficulty=0,
			nonce=0,
		)
		return Block(header=genesis_header, tx_hashes=[])

	@lazy_wrapper(SubmitTransactionPayload)
	def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload):
		if not self._is_approved_peer(peer):
			return

		if payload.sender_key.hex() not in self.allowed_key_hexes:
			self.ez_send(
				peer,
				SubmitTransactionResponsePayload(False, b"", "sender not allowed"),
			)
			return

		message = (
			payload.sender_key
			+ payload.data
			+ payload.timestamp.to_bytes(8, "big", signed=False)
		)
		try:
			signer_key = self.crypto.key_from_public_bin(payload.sender_key)
		except Exception:
			self.ez_send(
				peer,
				SubmitTransactionResponsePayload(False, b"", "bad sender key"),
			)
			return

		if not self.crypto.is_valid_signature(signer_key, message, payload.signature):
			self.ez_send(
				peer,
				SubmitTransactionResponsePayload(False, b"", "invalid signature"),
			)
			return

		tx_digest = tx_hash(payload.sender_key, payload.data, payload.timestamp, payload.signature)
		self.mempool.add((payload.sender_key, payload.data, payload.timestamp, payload.signature))
		self.ez_send(
			peer,
			SubmitTransactionResponsePayload(True, tx_digest, "accepted"),
		)

	@lazy_wrapper(SubmitTransactionResponsePayload)
	def on_submit_transaction_response(
		self,
		peer: Peer,
		payload: SubmitTransactionResponsePayload,
	):
		if not self._is_approved_peer(peer):
			return
		self.last_tx_response = payload

	@lazy_wrapper(GetChainHeightPayload)
	def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload):
		if not self._is_approved_peer(peer):
			return

		tip = self.blockchain.tip
		self.ez_send(
			peer,
			ChainHeightResponsePayload(payload.request_id, self.blockchain.chain_height, tip.header.hash()),
		)

	@lazy_wrapper(ChainHeightResponsePayload)
	def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponsePayload):
		if not self._is_approved_peer(peer):
			return
		self.peer_heights[peer.public_key.key_to_bin().hex()] = (payload.height, payload.tip_hash)

	@lazy_wrapper(GetBlockPayload)
	def on_get_block(self, peer: Peer, payload: GetBlockPayload):
		if not self._is_approved_peer(peer):
			return
		if payload.height < 0 or payload.height > self.blockchain.chain_height:
			return

		block = self.blockchain.get_chain(self.blockchain.tip)[payload.height]
		tx_hashes_blob = txs_hash(block.tx_hashes)
		self.ez_send(
			peer,
			BlockResponsePayload(
				payload.height,
				block.header.prev_hash,
				block.header.txs_hash,
				block.header.timestamp,
				block.header.difficulty,
				block.header.nonce,
				block.header.hash(),
				tx_hashes_blob,
			),
		)

	@lazy_wrapper(BlockResponsePayload)
	def on_block_response(self, peer: Peer, payload: BlockResponsePayload):
		if not self._is_approved_peer(peer):
			return
		if payload.height < 0:
			return
		if len(payload.prev_hash) != HASH_SIZE or len(payload.txs_hash) != HASH_SIZE:
			return
		if len(payload.block_hash) != HASH_SIZE:
			return
		try:
			body_hashes = split_tx_hashes(payload.tx_hashes)
		except ValueError:
			return

		expected_header_hash = block_hash(
			payload.prev_hash,
			payload.txs_hash,
			payload.timestamp,
			payload.difficulty,
			payload.nonce,
		)
		if expected_header_hash != payload.block_hash:
			return
		if not has_valid_pow(expected_header_hash, payload.difficulty):
			return
		if txs_hash(body_hashes) != payload.txs_hash:
			return

		if payload.height != self.blockchain.chain_height:
			return
		if payload.prev_hash != self.blockchain.tip.header.hash():
			return

		header = BlockHeader(
			prev_hash=payload.prev_hash,
			txs_hash=payload.txs_hash,
			timestamp=payload.timestamp,
			difficulty=payload.difficulty,
			nonce=payload.nonce,
		)
		self.blockchain.add_block(Block(header=header, tx_hashes=body_hashes))
		self.mempool.remove_confirmed(body_hashes)
