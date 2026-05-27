from __future__ import annotations

from pathlib import Path

from ipv8.keyvault.crypto import default_eccrypto

KEY_FILE = Path("my_ipv8_key.pem")


def load_public_key_hex(path: Path) -> str:
	with path.open("rb") as handle:
		private_key = default_eccrypto.key_from_private_bin(handle.read())
	public_key_bin = private_key.pub().key_to_bin()
	return public_key_bin.hex()


def main() -> None:
	if not KEY_FILE.exists():
		raise FileNotFoundError(f"Key file not found: {KEY_FILE}")
	print(load_public_key_hex(KEY_FILE))


if __name__ == "__main__":
	main()
