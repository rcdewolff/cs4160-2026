from ipv8.community import Community, CommunitySettings
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


class RegistrationCommunitySettings(CommunitySettings):
	should_register: bool = False


class RegistrationCommunity(Community):
	community_id = bytes.fromhex(DEFAULT_REGISTRATION_COMMUNITY_ID_HEX)
	settings_class = RegistrationCommunitySettings

	def __init__(self, settings):
		super().__init__(settings)

		self.add_message_handler(RegisterBlockchainPayload, self.on_register_blockchain)
		self.add_message_handler(RegisterBlockchainResponsePayload, self.on_register_blockchain_response)

		self.group_id = None
		self.blockchain_community_id = None
		self.registered = False
		self.should_register = getattr(settings, "should_register", False) is True

	def started(self) -> None:
		if not self.should_register:
			print("[Registration] Overlay loaded; automatic registration disabled.")
			return
		self.register_task("attempt_registration", self.attempt_registration, interval=2.0, delay=1.0)

	def set_registration_details(self, group_id: str, blockchain_community_id: bytes) -> None:
		self.group_id = group_id
		self.blockchain_community_id = blockchain_community_id

	def attempt_registration(self) -> None:
		if self.registered:
			self.cancel_pending_task("attempt_registration")
			return

		if not self.group_id or not self.blockchain_community_id:
			return

		server_peer = None
		for peer in self.get_peers():
			if peer.public_key.key_to_bin().hex() == DEFAULT_SERVER_PUBLIC_KEY_HEX:
				server_peer = peer
				break

		if server_peer:
			print(f"[Registration] Server found ({server_peer.public_key.key_to_bin().hex()[:10]}...). Registering...")
			self.ez_send(
				server_peer,
				RegisterBlockchainPayload(self.group_id, self.blockchain_community_id),
			)
		else:
			print("[Registration] Waiting for server peer...")

	@lazy_wrapper(RegisterBlockchainPayload)
	def on_register_blockchain(self, peer: Peer, payload: RegisterBlockchainPayload):
		# Server side (not implemented on node)
		pass

	@lazy_wrapper(RegisterBlockchainResponsePayload)
	def on_register_blockchain_response(self, peer: Peer, payload: RegisterBlockchainResponsePayload):
		if peer.public_key.key_to_bin().hex() != DEFAULT_SERVER_PUBLIC_KEY_HEX:
			return

		print(f"[Registration] Response from server: success={payload.success}, message={payload.message}")
		if payload.success:
			self.registered = True
			self.cancel_pending_task("attempt_registration")
