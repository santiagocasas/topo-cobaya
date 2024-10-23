import subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys
from eth_account import Account
from eth_utils import keccak
from pymerkle import InmemoryTree as MerkleTree
import os
import json
import yaml
import sys
import copy
from collections import OrderedDict
import importlib.util
import getpass

from .basic_cryptography import (
    get_commit_hash, compute_sha256, compute_file_hash
)
from .basic_utility import (
    ordered_load, remove_keys_recursive, print_in_red, find_specific_entries, is_power_of_two, load_proof_and_signatures_json
)




# Processing and verification
def process_file(file_path, skip=10, rounding=5):
    tree = MerkleTree(hash_type='sha256')
    roots = []
    with open(file_path, 'r') as f:
        for i, line in enumerate(f, start=1):
            if i % skip == 0:
                rounded_numbers = [round(float(num), rounding) for num in line.strip().split()]
                tree.append_entry(str(rounded_numbers).encode())
                if is_power_of_two(tree.get_size()):
                    roots.append(tree.get_state().hex())
    if not is_power_of_two(tree.get_size()):
        roots.append(tree.get_state().hex())
    return tree, roots

def automatic_check(pre_hash, pre_object, public_key):
    """
    Automatically verify the precommitted object and public key from stored JSON.
    """
    try:
        pre_object_stored, _, _, public_key_stored = load_proof_and_signatures_json(f'topo/cryptoFiles/pre_object_{pre_hash[:6]}.json')
        if pre_object_stored == pre_object:
            print('Automatic check passed')
        else:
            print('Automatic check failed. Precommitted values do not match. Please investigate further.')
        
        if public_key_stored != str(public_key):
            print('Public keys do not match. Please check.')
    except FileNotFoundError:
        print("No corresponding frozen analysis found. Please check manually. Also consider running FreezeAnalysis.py to generate one now for future use!")
    except Exception as e:
        print(f"Error during automatic check: {e}")


def process_file_and_verify_roots(file_path, proof_roots, skip=10, rounding=5, tree = None, position = 1, level = 1):
    if tree == None:
        tree = MerkleTree(hash_type='sha256')
    
    with open(file_path, 'r') as f:
        for i, line in enumerate(f, start=1):
            if i < position:
                continue
            if i % skip == 0:
                rounded_numbers = [round(float(num), rounding) for num in line.strip().split()]
                tree.append_entry(str(rounded_numbers).encode())
                #did we reach the top? 
                if tree.get_state().hex() == proof_roots[-1]:
                    #print('Full verification passed')
                    return -99,tree,i

                if is_power_of_two(tree.get_size()):
                    root_hash = tree.get_state().hex()
                    #print(root_hash)
                    #print(proof_roots)
                    if root_hash in proof_roots:
                        #if level >= current_level:
                            #print(f'Verification passed at level {level}')
                        level += 1
                    else:
                        print_in_red('Verification failed!')
                        return -1,tree,i
    return level, tree, i  


# Analysis functions
def compute_analysis_hash(input_path,params):

    git_hash = get_commit_hash() 
    try:
        with open(input_path, 'r') as file:
            input_yaml = ordered_load(file)
    except FileNotFoundError:
        print(f"Error: The file '{input_path}' was not found. Possibly your run does not correspond to a frozen analysis?")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if 'sampler' not in input_yaml:
        print("no sampler found in input_yaml!")
        sys.exit(1)
    if 'mcmc' not in input_yaml['sampler']:
        print('ananlysis is not running mcmc. Sampler not implemented yet')
        sys.exit(1)   
    exclude_keys = ["output", "likelihood", "seed"]
    filtered_input = remove_keys_recursive(copy.deepcopy(input_yaml), exclude_keys)
    input_hash = compute_sha256(str(filtered_input).encode()).hex()


    if 'code_versions' in params:
        code_versions = params['code_versions']
    else:
        code_versions = {}
    git_path_theory = ''
    git_hash_theory = ''
    require_user_input = False

    code_hashes = {}
    if 'theory' in input_yaml:
        for theory in input_yaml['theory']:

            if theory in code_versions:
                if 'hash' in code_versions[theory]:
                    git_hash_theory = code_versions[theory]['hash']
                elif 'path' in code_versions[theory]:
                    git_path_theory = code_versions[theory]['path']
                else:
                    require_user_input = True
            else:
                require_user_input = True
                # not found in data file
            if require_user_input:
                user_input = input(f"Do you want to enter a git repository path or a git hash for theory code {theory}? (Enter 'path' or 'hash'): ").strip().lower()

                if user_input == 'path':
                    # Ask for the path to the git repository
                    git_path_theory = input("Please provide the path to the git repository: ").strip()
                    
                elif user_input == 'hash':
                # Ask the user for the git hash directly
                    git_hash_theory = input("Please provide the git hash: ").strip()
                        
                else:
                    print("Invalid option. Please enter 'path' or 'hash'.")
                    sys.exit(1)

            
            if git_path_theory != '':
                git_hash_theory = get_commit_hash_from_path(git_path_theory)
                if require_user_input:
                    print(f"Obtained git hash for {theory}: {git_hash_theory} from {git_path_theory}.")
                else:
                    print_in_red(f"Obtained git hash for {theory}: {git_hash_theory} from {git_path_theory} found in params.json. Please verify this is the verison you are running!")
                
            else:
                if not require_user_input:
                    print_in_red(f"Obtained git hash for {theory}: {git_hash_theory} from params.json. Please verify this is the verison you are running!")
                

            if len(git_hash_theory) != 40:  # Simple check for valid SHA-1 hash length
                print("Invalid git hash.")
                sys.exit(1)

            code_hashes[theory] = git_hash_theory    
    

    pre_object = {'git_hash': git_hash, 'input_hash': input_hash, 'code_hashes': code_hashes}
    return pre_object, input_yaml


def compute_data_dict(input_yaml):
    data_dict = {'input_yaml_hash' : compute_sha256(str(input_yaml['likelihood']).encode()).hex()}
    for element in input_yaml['likelihood']:
        datapath = element.replace('.', '/')
        try:
            with open(f'cobaya/likelihoods/{datapath}.yaml', 'r') as file:
                data_yaml = yaml.safe_load(file)
        except: # no data exisits for this likelihood
            data_yaml = ''
        data_dict[element] = {'yaml_hash': compute_sha256(str(data_yaml).encode()).hex()}

        matches = find_specific_entries(data_yaml)
        for match in matches:
            match_hash = compute_file_hash(f'cosmo/data/{match}')
            data_dict[element][match] = match_hash
    #print(data_dict)
    return data_dict
