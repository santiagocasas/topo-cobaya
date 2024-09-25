from eth_account import Account
from utils import (
    save_proof_and_signatures_json, load_private_key, compute_analysis_hash,
    compute_data_dict, compute_sha256, sign_proof_object, automatic_check,
    load_proof_and_signatures_json, process_file
)
import sys 


# Main logic to generate proof after data analysis
if __name__ == "__main__":

    try:    
        input_path = sys.argv[1]  # First argument is expected to be the input file path
    except IndexError:
        print("Please specify the location of the input file.")
        sys.exit(1)  # Exit with a non-zero status to indicate an error

    # Collect any extra arguments beyond the input path
    extra_args = sys.argv[2:]  


    # Load private key and derive public key
    try:
        private_key = load_private_key("private_key.txt")
    except FileNotFoundError:
        print("No private key found. You can run Keygen.py to create a keypair.")
        sys.exit(1)  # Exit the program with a non-zero status to indicate failure
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    public_key = private_key.public_key
    account = Account.from_key(private_key)

    # Compute analysis hash and sign pre-object
    pre_object, input_yaml = compute_analysis_hash(input_path)
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
    print(output_file)
    _, roots = process_file(f'{output_file}.1.txt', skip=10, rounding=5)

    # Create the final proof object
    proof_object = {'roots': roots, 'data_hash': data_hash, 'seed': seed, 'Analysis_hash': pre_hash}
    
    # Sign the final proof object
    H_output, signatureB = sign_proof_object(private_key, proof_object)

    # Verify the final signature
    is_valid = public_key.verify_msg_hash(compute_sha256(str(proof_object).encode()), signatureB)

    print("\nPublish all of the following:")
    print(f"Committed main hash: {H_output}")
    print(f"Proof object: {proof_object}")
    print(f"Signature valid: {is_valid}")
    print(f"Signature: {signatureB}")
    print("\nAlso helpful for debugging the data:")
    print(data_dict)
    # Save proof object, signatures, and public key to JSON
    save_proof_and_signatures_json(f'proof_object_{pre_hash[:6]}_{ident[:6]}.json', proof_object, signatureA, signatureB, public_key)
    print('Proof-object saved in JSON')

