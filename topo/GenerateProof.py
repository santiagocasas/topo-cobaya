from eth_account import Account
from basic_cryptography import (
    load_private_key, compute_sha256, sign_proof_object,
)
from basic_utility import (
    save_proof_and_signatures_json, load_proof_and_signatures_json, load_json
)
from analysis import compute_analysis_hash, compute_data_dict, automatic_check, process_file
import sys 
import os
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate proof after data analysis.")
    parser.add_argument("input_path", nargs="?", help="Path to the input file")
    parser.add_argument("-p", "--path", help="Path to the input file (alternative to positional argument)")
    return parser.parse_args()

def main(args):
    # Determine input path
    input_path = args.input_path or args.path
    if not input_path:
        print("Please specify the location of the input file using either a positional argument or -p/--path option.")
        sys.exit(1)

    # Load private key and derive public key
    params = load_json('topo/params.json')
    
    try:
        private_key = load_private_key(params['key_path'])
    except FileNotFoundError:
        print(f"No private key found at {params['key_path']}. You can run Keygen.py to create a new keypair or update params.json to your keypath.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    public_key = private_key.public_key
    account = Account.from_key(private_key)

    # Compute analysis hash and sign pre-object
    pre_object, input_yaml = compute_analysis_hash(input_path, params)
    pre_hash, signatureA = sign_proof_object(private_key, pre_object)

    # Display precommitted hash and object for verification
    print("\nPlease verify that this matches your precommitted analysis")
    print(f"Analysis hash: {pre_hash}")
    print(pre_object)

    # Perform automatic verification of precommitted values
    automatic_check(pre_hash, pre_object, public_key)

    # Extract seed and compute data hash
    seed = input_yaml['sampler']['mcmc']['seed']
    data_dict = compute_data_dict(input_yaml)
    data_hash = compute_sha256(str(data_dict).encode()).hex()

    # Create a unique identifier for this run
    ident = compute_sha256(str([data_hash,seed]).encode()).hex()

    # Process the output file to obtain Merkle roots
    output_file = input_yaml['output']
    if 'skip' not in params:
        print_in_red("skip not found in params.json. Using default of 10.")
        params['skip'] = 10
    if 'round' not in params:
        print_in_red("round not found in params.json. Using default of 5.")
        params['round'] = 5

    _, roots = process_file(f'{output_file}.1.txt', skip=params['skip'], rounding=params['round'])

    # Create the final proof object
    proof_object = {'roots': roots, 'data_hash': data_hash, 'seed': seed, 'skip': params['skip'], 'round': params['round'], 'Analysis_hash': pre_hash}
    
    # Sign the final proof object
    H_output, signatureB = sign_proof_object(private_key, proof_object)

    # Verify the final signature
    is_valid = public_key.verify_msg_hash(compute_sha256(str(proof_object).encode()), signatureB)

    print("\nPublish all of the following:")
    print(f"Committed main hash: {H_output}")
    print(f"Proof object: {proof_object}")
    print(f"Signature: {signatureB}")

    # Save proof object, signatures, and public key to JSON
    save_proof_and_signatures_json(f'topo/cryptoFiles/proof_object_{pre_hash[:6]}_{ident[:6]}.json', proof_object, signatureA, signatureB, public_key)
    print('Proof-object saved in JSON')

if __name__ == "__main__":
    args = parse_arguments()
    main(args)

