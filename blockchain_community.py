from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer


DEFAULT_REGISTRATION_COMMUNITY_ID_HEX = "4c616233426c6f636b636861696e323032365057"
DEFAULT_SERVER_PUBLIC_KEY_HEX = (
	"4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4"
	"350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f"
	"791324495e083331ce6"
)


# Registration community payloads.
@vp_compile
class RegisterBlockchainPayload(VariablePayload):
	msg_id = 1

	format_list = ["varlenHutf8", "varlenH"]
	names = ["group_id", "community_id"]


@vp_compile
class RegisterBlockchainResponsePayload(VariablePayload):
	msg_id = 2

	format_list = ["?", "varlenHutf8"]
	names = ["success", "message"]


class RegistrationCommunity(Community):
	community_id = bytes.fromhex(DEFAULT_REGISTRATION_COMMUNITY_ID_HEX)

	def __init__(self, settings):
		super().__init__(settings)

		self.add_message_handler(RegisterBlockchainPayload, self.on_register_blockchain)
		self.add_message_handler(RegisterBlockchainResponsePayload, self.on_register_blockchain_response)

	@lazy_wrapper(RegisterBlockchainPayload)
	def on_register_blockchain(self, peer: Peer, payload: RegisterBlockchainPayload):
		pass

	@lazy_wrapper(RegisterBlockchainResponsePayload)
	def on_register_blockchain_response(self, peer: Peer, payload: RegisterBlockchainResponsePayload):
		pass


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


class BlockchainCommunity(Community):
	community_id = bytes(20)

	def __init__(self, settings):
		super().__init__(settings)

		self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
		self.add_message_handler(SubmitTransactionResponsePayload, self.on_submit_transaction_response)
		self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
		self.add_message_handler(ChainHeightResponsePayload, self.on_chain_height_response)
		self.add_message_handler(GetBlockPayload, self.on_get_block)
		self.add_message_handler(BlockResponsePayload, self.on_block_response)

	@lazy_wrapper(SubmitTransactionPayload)
	def on_submit_transaction(self, peer: Peer, payload: SubmitTransactionPayload):
		pass

	@lazy_wrapper(SubmitTransactionResponsePayload)
	def on_submit_transaction_response(
		self,
		peer: Peer,
		payload: SubmitTransactionResponsePayload,
	):
		pass

	@lazy_wrapper(GetChainHeightPayload)
	def on_get_chain_height(self, peer: Peer, payload: GetChainHeightPayload):
		pass

	@lazy_wrapper(ChainHeightResponsePayload)
	def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponsePayload):
		pass

	@lazy_wrapper(GetBlockPayload)
	def on_get_block(self, peer: Peer, payload: GetBlockPayload):
		pass

	@lazy_wrapper(BlockResponsePayload)
	def on_block_response(self, peer: Peer, payload: BlockResponsePayload):
		pass
