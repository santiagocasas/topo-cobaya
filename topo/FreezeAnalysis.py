from eth_account import Account

from .basic_cryptography import (
    load_private_key, compute_sha256,
    sign_proof_object,
    
)
from .basic_utility import load_json, save_proof_and_signatures_json
from .analysis import compute_analysis_hash

import sys
import os
import argparse

def main(args):
    # Load private key and derive public key

    params = load_json('topo/params.json')
    
    try:
        private_key = load_private_key(params['key_path'])
    except FileNotFoundError:
        print(f"No private key found at {params['key_path']}. You can run Keygen.py to create a new keypair or update params.json to match your keypath.")
        sys.exit(1)  # Exit the program with a non-zero status to indicate failure
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    public_key = private_key.public_key

    # Generate account from private key (Ethereum address)
    account = Account.from_key(private_key)

    # Compute analysis hash and sign the pre-object
    pre_object, _ = compute_analysis_hash(args.input_path, params)
    pre_hash, signature = sign_proof_object(private_key, pre_object)

    # Verify the signature
    message_hash = compute_sha256(str(pre_object).encode())
    is_valid = public_key.verify_msg_hash(message_hash, signature)

    print("\nInformation to publish with timestamp:")
    print(f"Analysis hash: {pre_hash}")
    print(f"Signature: {signature}")
    #print(f"Testing Signature: {is_valid}")

    print("\nPublish now, or later if code is still secret")
    print(f"The input file, and the git branch including the versions of installed theory codes")
    print(f"Those should match these hashes {pre_object}")

    # Save the pre-object and signatures to a JSON file
    save_proof_and_signatures_json(f'topo/cryptoFiles/pre_object_{pre_hash[:6]}.json', pre_object, signature, None, public_key)
    print(f'Pre-object saved in JSON format at topo/cryptoFiles/pre_object_{pre_hash[:6]}.json')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and sign analysis hash for input file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("input_path", nargs="?", help="Path to the cobaya input file for analysis. Example: scripts/my_input.yaml")
    group.add_argument("-p", "--path", help="Alternative way to specify the path to the cobaya input file")
    args = parser.parse_args()

    # If --path is used, set input_path to its value
    if args.path:
        args.input_path = args.path

    main(args)
