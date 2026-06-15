import unittest
from unittest.mock import MagicMock

from registration_community import (
	RegistrationCommunity,
	RegisterBlockchainPayload,
	RegisterBlockchainResponsePayload,
	DEFAULT_SERVER_PUBLIC_KEY_HEX,
)

class TestRegistrationCommunity(unittest.IsolatedAsyncioTestCase):
	def test_registration_attempt_sends_payload_when_server_discovered(self):
		settings = MagicMock()
		community = RegistrationCommunity(settings)
		community.group_id = "test_group"
		community.blockchain_community_id = b"blockchain_comm_id_1"

		server_peer = MagicMock()
		server_peer.public_key.key_to_bin().hex.return_value = DEFAULT_SERVER_PUBLIC_KEY_HEX

		community.get_peers = MagicMock(return_value=[server_peer])
		community.ez_send = MagicMock()

		community.attempt_registration()

		community.ez_send.assert_called_once()
		called_peer, called_payload = community.ez_send.call_args[0]
		self.assertEqual(called_peer, server_peer)
		self.assertIsInstance(called_payload, RegisterBlockchainPayload)
		self.assertEqual(called_payload.group_id, "test_group")
		self.assertEqual(called_payload.community_id, b"blockchain_comm_id_1")

	def test_registration_does_not_send_when_server_not_discovered(self):
		settings = MagicMock()
		community = RegistrationCommunity(settings)
		community.group_id = "test_group"
		community.blockchain_community_id = b"blockchain_comm_id_1"

		other_peer = MagicMock()
		other_peer.public_key.key_to_bin().hex.return_value = "other_key_hex"

		community.get_peers = MagicMock(return_value=[other_peer])
		community.ez_send = MagicMock()

		community.attempt_registration()

		community.ez_send.assert_not_called()

	def test_registration_success_stops_task(self):
		settings = MagicMock()
		community = RegistrationCommunity(settings)
		community.cancel_pending_task = MagicMock()

		server_peer = MagicMock()
		server_peer.public_key.key_to_bin().hex.return_value = DEFAULT_SERVER_PUBLIC_KEY_HEX

		payload = RegisterBlockchainResponsePayload(success=True, message="Registered successfully")

		community.on_register_blockchain_response.__wrapped__(community, server_peer, payload)

		self.assertTrue(community.registered)
		community.cancel_pending_task.assert_called_once_with("attempt_registration")

	def test_registration_failure_keeps_task_running(self):
		settings = MagicMock()
		community = RegistrationCommunity(settings)
		community.cancel_pending_task = MagicMock()

		server_peer = MagicMock()
		server_peer.public_key.key_to_bin().hex.return_value = DEFAULT_SERVER_PUBLIC_KEY_HEX

		payload = RegisterBlockchainResponsePayload(success=False, message="Registration failed")

		community.on_register_blockchain_response.__wrapped__(community, server_peer, payload)

		self.assertFalse(community.registered)
		community.cancel_pending_task.assert_not_called()

if __name__ == "__main__":
	unittest.main()
