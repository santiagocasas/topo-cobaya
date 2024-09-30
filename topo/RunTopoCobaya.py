from eth_account import Account

from basic_cryptography import (
    load_private_key, compute_sha256, sign_proof_object,
)
from basic_utility import (
    save_proof_and_signatures_json, load_proof_and_signatures_json, load_json, ordered_dump
)
from analysis import compute_analysis_hash, compute_data_dict, automatic_check, process_file
import os
import subprocess
import sys

# Main logic to generate proof after data analysis
def main():


    try:    
        input_path = sys.argv[1]  # First argument is expected to be the input file path
        
        name = os.path.splitext(os.path.basename(input_path))[0]

    except IndexError:
        print("Please specify the location of the input file.")
        sys.exit(1)  # Exit with a non-zero status to indicate an error

    # Collect any extra arguments beyond the input path
    extra_args = sys.argv[2:]  

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
    account = Account.from_key(private_key)

    # Compute analysis hash and sign pre-object
    pre_object, input_yaml = compute_analysis_hash(input_path,params)
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
    # Try to see if this has already been used and finalized as proof
    proof_path = f'topo/cryptoFiles/proof_object_{pre_hash[:6]}_{ident[:6]}.json'

    if os.path.exists(proof_path):
        user_input = input(
            "These parameters have already been run. For a new run, you might consider changing the seed.\n"
            "Rerun with the same parameters? Enter (yes/no), or provide a number for a new seed: "
        ).strip().lower()

        if user_input == 'no':
            print("Aborting run.")
            return
        elif user_input == 'yes':
            print("Rerunning with the same parameters.")
        else:
            try:
                # Attempt to interpret the input as an integer (new seed)
                new_seed = int(user_input)
                print(f"Running with a new seed: {new_seed}")
                input_yaml['sampler']['mcmc']['seed'] = new_seed
                # get new ident
                ident = compute_sha256(str([data_hash,new_seed]).encode()).hex()
    

            except ValueError:
                print("Invalid input! Expected 'yes', 'no', or a number for a new seed. Aborting run.")
                return


    # Save yaml after modiufications and define canonical output 
    input_yaml['output'] = input_yaml['output'] + f'_{pre_hash[:6]}_{ident[:6]}'

    with open(f'scripts/{name}_{pre_hash[:6]}_{ident[:6]}.yaml', 'w') as file:
        ordered_dump(input_yaml, file, default_flow_style=False)

    # Run Cobaya
    command = ["cobaya-run", f"scripts/{name}_{pre_hash[:6]}_{ident[:6]}.yaml"]
    #command += extra_args
    cobaya = subprocess.run(command)

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
    #print(f"Signature valid: {is_valid}")
    print(f"Signature: {signatureB}")
    print("\nAlso helpful for debugging the data:")
    print(data_dict)
    # Save proof object, signatures, and public key to JSON
    save_proof_and_signatures_json(f'topo/cryptoFiles/proof_object_{pre_hash[:6]}_{ident[:6]}.json', proof_object, signatureA, signatureB, public_key)
    print('Proof-object saved in JSON')

if __name__ == "__main__":
    main()