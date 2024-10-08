from eth_account import Account

from basic_cryptography import (
    load_private_key, compute_sha256,
    sign_proof_object,
    
)
from basic_utility import load_json, save_proof_and_signatures_json
from analysis import compute_analysis_hash

import sys
import os
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate and sign analysis hash for input file.")
    parser.add_argument("input_path", help="Path to the cobaya input file for analysis. Example: scripts/my_input.yaml")
    parser.add_argument("extra_args", nargs="*", help="Path to the code versions .json file that specifies the theory code used. Example: topo/code_versions.json")
    return parser.parse_args()

def main(args):
    # Load private key and derive public key

    params = load_json('topo/params.json')
    
    try:
        private_key = load_private_key(params['key_path'])
    except FileNotFoundError:
        print(f"No private key found at {params['key_path']}. You can run Keygen.py to create a new keypair or update params.json to your keypath.")
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
    print('Pre-object saved in JSON')

if __name__ == "__main__":
    args = parse_arguments()
    main(args)


