from .basic_cryptography import generate_keys, save_private_key, load_private_key
from .basic_utility import load_json

from eth_keys import keys
from eth_account import Account
import sys
import json
import argparse

def main(args):
    if args.load:
        # Load an existing private key
        key_path = args.load
        try:
            private_key = load_private_key(key_path)
            params = load_json('topo/params.json')
            params['key_path'] = key_path
            with open('topo/params.json', 'w') as f:
                json.dump(params, f, indent=4)
            print(f"Private key loaded from {key_path}")
        except FileNotFoundError:
            print(f"Error: The private key file '{key_path}' was not found.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while loading the private key: {e}")
            sys.exit(1)
    else:
        # Ask for user confirmation before generating a new key
        confirm = input("No existing key specified. Do you want to generate a new private key? (yes/no): ").strip().lower()
        if confirm == 'yes':
            print("Generating a new private key...")
            private_key = generate_keys()
            save_private_key(private_key)
            print("New private key generated and saved.")
        else:
            print("Key generation cancelled. Use --load to specify an existing key.")
            sys.exit(0)

    # Derive the public key and Ethereum account from the private key
    public_key = private_key.public_key
    account = Account.from_key(private_key)

    # Output the public key and Ethereum address
    print("\nIf not known publicly yet: publish")
    print(f"Public Key: {public_key}")
    print(f"Ethereum Address: {account.address}")

    print("Please keep the corresponding private key safe.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate or load cryptographic keys for Topo-Cobaya.")
    parser.add_argument("--load", metavar="KEY_PATH", help="Load an existing private key from the specified path")
    args = parser.parse_args()
    main(args)
