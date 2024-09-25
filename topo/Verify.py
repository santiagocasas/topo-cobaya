from utils import (
    compute_sha256, get_commit_hash, compute_file_hash, compute_analysis_hash, 
    compute_data_dict, process_file_and_verify_roots, load_proof_and_signatures_json, 
    verify_committed_hash, verify_signature_hex, remove_keys_recursive, ordered_load, ordered_dump
)
from ascii_magic import AsciiArt
import os
import time
import subprocess
import copy
import sys


def verify_pre_object(pre_hash, proof, public_key_hex, signature_hex):
    """
    Verifies the pre-object's analysis hash and signature.
    """
    # Verify the committed pre-object hash
    if pre_hash == proof['Analysis_hash']:
        print('Analysis hash verified: You are running the correct analysis pipeline.')
    else:
        print('Committed hash not verified: The code or input file version might be incorrect.')
        return False

    # Verify the signature on the pre-object
    if verify_signature_hex(public_key_hex, bytes.fromhex(pre_hash), signature_hex):
        print('Signature valid: Prover authenticity established.')
        return True
    else:
        print('Signature invalid: Could not authenticate the analysis hash.')
        return False


def verify_proof_object(proof, public_key_hex, signatureB):
    """
    Verifies the proof object and its signature.
    """
    proof_hash = compute_sha256(str(proof).encode())
    if verify_signature_hex(public_key_hex, proof_hash, signatureB):
        print('Proof signature valid: Identity and proof object verified.')
        return True
    else:
        print('Signature invalid: Proof object may have been tampered with or prover authenticity cannot be confirmed.')
        return False


def verify_data(data_hash, input_yaml, proof):
    """
    Verifies the data hash against the proof.
    """
    if data_hash == proof['data_hash']:
        print('Data verified: You are running with the correct dataset.')
        return True
    else:
        print('Data not verified.')
        return False


def run_verification(pre_hash, ident, input_yaml, proof, extra_args):
    """
    Executes the verification process and monitors the output in real-time.
    """
    # Prepare new YAML for verification
    new_yaml = copy.deepcopy(input_yaml)
    new_yaml['output'] = f'chains/Verification_{pre_hash[:6]}_{ident[:6]}'

    with open(f'scripts/Verification_{pre_hash[:6]}_{ident[:6]}.yaml', 'w') as file:
        ordered_dump(new_yaml, file, default_flow_style=False)

    # Run the verification command
    command = ["cobaya-run", f"scripts/Verification_{pre_hash[:6]}_{ident[:6]}.yaml"]
    command += extra_args
    cobaya = subprocess.Popen(command)

    current_level = 0
    while cobaya.poll() is None:
        print("Verification running...")

        time.sleep(90)  # Check progress every minute
        file_path = f"chains/Verification_{pre_hash[:6]}_{ident[:6]}.1.txt"
        #print(file_path)
        if os.path.exists(file_path):
            new_level = process_file_and_verify_roots(file_path, proof['roots'], skip=10, rounding=5, current_level=current_level)
            if new_level > current_level:
                current_level = new_level
                print(f"Congratulations, your topology has reached level {current_level}!!!")
                try:
                    my_art = AsciiArt.from_image(f'topo/asciiart/level_{current_level}.png')
                    my_art.to_terminal(columns=100)
                except FileNotFoundError:
                    print(f"Error: The file topo/asciiart/level_{current_level}.png was not found. If you want level-up immages put something there!")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")


    print('Reached full verification')
    process_file_and_verify_roots(f"Verification_{pre_hash[:6]}_{ident[:6]}.1.txt", proof['roots'], skip=10, rounding=5, full_verification=True)


if __name__ == "__main__":

    try:    
        input_path = sys.argv[1]  # First argument is expected to be the input file path
    except IndexError:
        print("Please specify the location of the input file.")
        sys.exit(1)  # Exit with a non-zero status to indicate an error

    # Collect any extra arguments beyond the input path
    extra_args = sys.argv[2:]  


    # Flag to control whether the code should be run after verifications
    run_code = True

    # Compute analysis hash and pre-object
    pre_object, input_yaml = compute_analysis_hash(input_path)
    pre_hash = compute_sha256(str(pre_object).encode()).hex()

    # Compute data hashes and run identifier
    seed = input_yaml['sampler']['mcmc']['seed']
    data_dict = compute_data_dict(input_yaml)
    data_hash = compute_sha256(str(data_dict).encode()).hex()

    ident = compute_sha256(str([data_hash,seed]).encode()).hex()

    

    # Load the proof object, signatures, and public key
    try:
        proof, signature_hex, signatureB, public_key_hex = load_proof_and_signatures_json(f"topo/cryptoFiles/proof_object_{pre_hash[:6]}_{ident[:6]}.json")
    except FileNotFoundError:
        print("Error: Proof object file not found. Exiting.")
        run_code = False

    # Step 1: Verify the pre-object and its signature
    if run_code:
        run_code = verify_pre_object(pre_hash, proof, public_key_hex, signature_hex)

    # Step 2: Verify the full proof object and its signature
    if run_code:
        run_code = verify_proof_object(proof, public_key_hex, signatureB)

    # Step 3: Verify the data
    if run_code:
        run_code = verify_data(data_hash, input_yaml, proof)

    # Step 4: If all verifications passed, proceed with running the analysis
    if run_code:
        run_verification(pre_hash, ident, input_yaml, proof, extra_args)
    else:
        print('Verification failed: Process aborted.')
