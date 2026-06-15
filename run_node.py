import argparse
import asyncio
import os
import sys

from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8
from ipv8.util import run_forever

from registration_community import RegistrationCommunity, DEFAULT_SERVER_PUBLIC_KEY_HEX
from blockchain_community import BlockchainCommunity

class CustomBlockchainCommunity(BlockchainCommunity):
	pass


def _short_key(key_hex: str) -> str:
	return f"{key_hex[:10]}..." if len(key_hex) > 10 else key_hex


async def wait_for_teammates(blockchain_overlay: BlockchainCommunity, teammate_hexes: list[str]) -> None:
	expected = set(teammate_hexes)
	if not expected:
		print("[Registration] No teammate keys configured; registration readiness gate is open.")
		return

	print(f"[Registration] Waiting for {len(expected)} teammate(s) in the blockchain community before registering...")
	last_report = 0.0
	while True:
		seen = {
			peer.public_key.key_to_bin().hex().lower()
			for peer in blockchain_overlay.get_peers()
		}
		missing = expected - seen
		if not missing:
			print("[Registration] All teammates discovered. Registration can start.")
			return

		now = asyncio.get_running_loop().time()
		if now - last_report >= 5.0:
			missing_keys = ", ".join(_short_key(key) for key in sorted(missing))
			print(f"[Registration] Still waiting for teammate(s): {missing_keys}")
			last_report = now

		await asyncio.sleep(1.0)


async def main() -> None:
	parser = argparse.ArgumentParser(description="Run a Lab 3 Blockchain Node")
	parser.add_argument("--key", type=str, default="lab1_key.pem", help="Path to private key PEM file")
	parser.add_argument("--port", type=int, default=8090, help="IPv8 listening port")
	parser.add_argument("--group-id", type=str, required=True, help="Lab 2 Group ID")
	parser.add_argument("--community-id", type=str, default="68726973746F7261706861656C6A65726F656E31", help="20-byte custom blockchain community ID in hex (40 chars)")
	parser.add_argument("--teammates", type=str, default="", help="Comma-separated public key hexes of teammates")
	parser.add_argument("--server-key", type=str, default=DEFAULT_SERVER_PUBLIC_KEY_HEX, help="Server public key hex")
	parser.add_argument("--register", action="store_true", help="The person who registers the group")

	args = parser.parse_args()

	# Validate community_id length
	try:
		comm_id_bytes = bytes.fromhex(args.community_id)
		if len(comm_id_bytes) != 20:
			raise ValueError("Community ID must be exactly 20 bytes.")
	except ValueError as e:
		print(f"Error: Invalid --community-id: {e}")
		sys.exit(1)

	# Parse teammates
	teammate_hexes = [pk.strip().lower() for pk in args.teammates.split(",") if pk.strip()]
	if args.register and len(set(teammate_hexes)) != 2:
		print("Error: --register requires exactly two teammate public keys in --teammates.")
		sys.exit(1)

	# Set the custom community ID for the blockchain community subclass
	CustomBlockchainCommunity.community_id = comm_id_bytes

	# Prepare allowed keys
	allowed_keys = {args.server_key.lower()}
	for pk in teammate_hexes:
		allowed_keys.add(pk)

	print(f"Starting IPv8 node on port {args.port}...")
	print(f"Group ID: {args.group_id}")
	print(f"Blockchain Community ID: {args.community_id}")
	print(f"Teammates: {teammate_hexes}")
	print(f"Allowed Keys: {allowed_keys}")
	print(f"Registration: {'enabled' if args.register else 'disabled'}")

	# Build IPv8 configuration
	builder = ConfigBuilder().clear_keys().clear_overlays()
	builder.set_port(args.port)
	builder.add_key("my peer", "curve25519", args.key)

	# Every node joins the registration community so it has the message handlers loaded.
	# Only the node started with --register schedules the periodic registration task.
	builder.add_overlay(
		"RegistrationCommunity",
		"my peer",
		[WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
		default_bootstrap_defs,
		{"should_register": args.register},
		[("started",)],
	)

	# Add Custom Blockchain Overlay
	builder.add_overlay(
		"CustomBlockchainCommunity",
		"my peer",
		[WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
		default_bootstrap_defs,
		{"allowed_key_hexes": allowed_keys, "server_key_hex": args.server_key.lower()},
		[("started",)],
	)

	# Start IPv8 instance
	ipv8 = IPv8(
		builder.finalize(),
		extra_communities={
			"RegistrationCommunity": RegistrationCommunity,
			"CustomBlockchainCommunity": CustomBlockchainCommunity,
		}
	)

	await ipv8.start()

	# Retrieve the instantiated communities
	registration_overlay = None
	blockchain_overlay = None
	for overlay in ipv8.overlays:
		if isinstance(overlay, RegistrationCommunity):
			registration_overlay = overlay
		elif isinstance(overlay, CustomBlockchainCommunity):
			blockchain_overlay = overlay

	if not registration_overlay:
		print("Error: RegistrationCommunity failed to load.")
		sys.exit(1)

	if not blockchain_overlay:
		print("Error: CustomBlockchainCommunity failed to load.")
		sys.exit(1)

	# Ensure our own public key is also added to the allowed keys in the blockchain community
	my_pubkey_hex = blockchain_overlay.my_peer.public_key.key_to_bin().hex()
	blockchain_overlay.allowed_key_hexes.add(my_pubkey_hex)
	print(f"My public key: {my_pubkey_hex}")

	if args.register:
		await wait_for_teammates(blockchain_overlay, teammate_hexes)
		# Configure registration details after teammate discovery; the registration task will
		# send once it also discovers the official server peer.
		registration_overlay.set_registration_details(args.group_id, comm_id_bytes)

	print("IPv8 node started successfully. Running forever...")
	await run_forever()

if __name__ == "__main__":
	asyncio.run(main())
