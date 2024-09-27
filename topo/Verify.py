from utils import (
    compute_sha256, get_commit_hash, compute_file_hash, compute_analysis_hash, 
    compute_data_dict, process_file_and_verify_roots, load_proof_and_signatures_json, 
    verify_committed_hash, verify_signature_hex, remove_keys_recursive, ordered_load, ordered_dump, load_json_if_present
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
    new_yaml['output'] = f'chains/Verification/{name}_{pre_hash[:6]}_{ident[:6]}'
    os.makedirs("scripts/Verification", exist_ok=True)
    
    with open(f'scripts/Verification/{name}_{pre_hash[:6]}_{ident[:6]}.yaml', 'w') as file:
        ordered_dump(new_yaml, file, default_flow_style=False)

    # check if this was already run
    output_file = new_yaml['output']
    file_path = f"{output_file}.1.txt"

    run_code = True

    if os.path.exists(file_path):
        user_input = input(
            "This verification has already been run. Rerun with the same parameters? Enter (yes/no): "
        ).strip().lower()

        if user_input == 'no':
            print("Proceeding with verification")
            run_code = False
        elif user_input == 'yes':
            print("Rerunning with the same parameters.")
    if run_code:
        # Run the verification command
        command = ["cobaya-run", f"scripts/Verification/{name}_{pre_hash[:6]}_{ident[:6]}.yaml"]
        #command += extra_args
        cobaya = subprocess.Popen(command)

        print("Verification running...")

        time.sleep(4)
        user_input = input(" How long should the verification run in minutes (Negative numbers mean open ended runs)?").strip().lower()

        try:
            # Convert the input to an integer
            verification_time = int(user_input)
            print(f"Verification will run for {verification_time} minutes.")
            
        except ValueError:
            print("Invalid input. Please enter a valid integer. Running open end")
            verification_time  = -1

        verification_time *= 60

        current_level = 0
        time_spent = 0  
        i = 0
        
        while ((cobaya.poll() is None) or (i == 0)) and ((time_spent < verification_time) or (verification_time < 0)):

            
            
            #print(file_path)
            if os.path.exists(file_path):
                if i == 0:
                    level, tree, i = process_file_and_verify_roots(file_path, proof['roots'], skip=proof['skip'], rounding=proof['round'], level = 1)
                else:
                    level, tree, i = process_file_and_verify_roots(file_path, proof['roots'], skip=proof['skip'], rounding=proof['round'],tree = tree, position = i+1, level = level)
                
                if level > current_level:
                    current_level = level
                    print(f"Congratulations, your topology has reached level {level-2}!!!")
                    try:
                        my_art = AsciiArt.from_image(f'topo/asciiart/level_{level-2}.png')
                        my_art.to_terminal(columns=100)
                    except FileNotFoundError:
                        print(f"Error: The file topo/asciiart/level_{level-2}.png was not found. If you want level-up immages put something there!")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")
                elif level == 0:
                    print("Verification chain not found!")
                elif level == -1:
                    print("Verification failed! Stoppoing cobaya! ")
                    cobaya.terminate()  # Use terminate to allow for a graceful shutdown

                    try:
                        my_art = AsciiArt.from_image(f'topo/asciiart/dead.png')
                        my_art.to_terminal(columns=100)
                    except FileNotFoundError:
                        print(f"Error: The file topo/asciiart/dead.png was not found. If you want level-up immages put something there!")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")
                
                    return
                elif level == -99:
                    print("Full Verfiication completed! Stoppoing cobaya! ")
                    cobaya.terminate()  # Use terminate to allow for a graceful shutdown

                    try:
                        my_art = AsciiArt.from_image(f'topo/asciiart/victory.png')
                        my_art.to_terminal(columns=100)
                    except FileNotFoundError:
                        print(f"Error: The file topo/asciiart/victory.png was not found. If you want level-up immages put something there!")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")
                
                    return

            time.sleep(89)  # Check progress every 89 seconds
            time_spent += 89
            
        cobaya.terminate()
    else: # not running the code
        level, _,_ = process_file_and_verify_roots(file_path, proof['roots'], skip=proof['skip'], rounding=proof['round'], level = 1)

                
        if level > 0:
            print(f"Congratulations, your topology has reached level {level-2}!!!")
            try:
                my_art = AsciiArt.from_image(f'topo/asciiart/level_{level-2}.png')
                my_art.to_terminal(columns=100)
            except FileNotFoundError:
                print(f"Error: The file topo/asciiart/level_{level-2}.png was not found. If you want level-up immages put something there!")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        elif level == -1:
            print("Verification failed! ")
            try:
                my_art = AsciiArt.from_image(f'topo/asciiart/dead.png')
                my_art.to_terminal(columns=100)
            except FileNotFoundError:
                print(f"Error: The file topo/asciiart/dead.png was not found. If you want level-up immages put something there!")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        
            
        elif level == -99:
            print("Full Verfiication completed! ")
            
            try:
                my_art = AsciiArt.from_image(f'topo/asciiart/victory.png')
                my_art.to_terminal(columns=100)
            except FileNotFoundError:
                print(f"Error: The file topo/asciiart/victory.png was not found. If you want level-up immages put something there!")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        
        

if __name__ == "__main__":

    try:    
        input_path = sys.argv[1]  # First argument is expected to be the input file path
        name = os.path.splitext(os.path.basename(input_path))[0]
        name = name.split('_', 1)[0]

    except IndexError:
        print("Please specify the location of the input file.")
        sys.exit(1)  # Exit with a non-zero status to indicate an error


    # Collect any extra arguments beyond the input path
    extra_args = sys.argv[2:]  

    params = load_json_if_present(['topo/params.json'])
    

    # Flag to control whether the code should be run after verifications
    run_code = True

    # Compute analysis hash and pre-object
    pre_object, input_yaml = compute_analysis_hash(input_path,params)
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
        print(f"Error: Proof object file not found at topo/cryptoFiles/proof_object_{pre_hash[:6]}_{ident[:6]}.json. Exiting.")
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
