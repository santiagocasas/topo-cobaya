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


# Utility functions
def compute_sha256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()


def is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0


# Key management
def load_private_key(file_path):
    with open(file_path, "rb") as f:
        private_key_bytes = f.read()
    return keys.PrivateKey(private_key_bytes)


def generate_keys():
    private_key_bytes = os.urandom(32)
    private_key = keys.PrivateKey(private_key_bytes)

    if os.path.exists("topo/cryptoFiles/private_key.txt"):
        user_input = input("Key file already exists. Do you want to overwrite it? (yes/no): ").strip().lower()
        if user_input != 'yes':
            print("Aborting key generation to avoid overwriting.")
            return

    with open("topo/private_key.txt", "wb") as f:
        f.write(private_key_bytes)
    print("Keys generated and saved to private_key.txt.")

    public_key = private_key.public_key

    # Generate account from private key (Ethereum address)
    account = Account.from_key(private_key)


    print("\nIf not known publicly yet: publish")
    print(f"Public Key: {public_key}")
    print(f"Ethereum Address: {account.address}")

    print("Please keep corresponding private key safe")



# File and directory hashing
def compute_file_hash(file_path):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize().hex()


def compute_directory_hash(directory_path):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for root, dirs, files in sorted(os.walk(directory_path)):
        for file in sorted(files):
            file_path = os.path.join(root, file)
            file_hash = compute_file_hash(file_path)
            relative_file_path = os.path.relpath(file_path, directory_path)
            digest.update(relative_file_path.encode())
            digest.update(file_hash.encode())
    return digest.finalize().hex()


# Signing and verification
def sign_message(private_key, message):
    message_hash = compute_sha256(message)
    signature = private_key.sign_msg_hash(message_hash)
    return signature


def verify_signature(public_key, message, signature):
    message_hash = compute_sha256(message)
    return public_key.verify_msg_hash(message_hash, signature)


def verify_committed_hash(object_to_hash, committed_hash):
    computed_hash = compute_sha256(str(object_to_hash).encode()).hex()
    return computed_hash == committed_hash


def verify_signature_hex(public_key_hex, message_hash, signature_hex):
    public_key_bytes = bytes.fromhex(public_key_hex[2:])
    public_key = keys.PublicKey(public_key_bytes)
    signature_bytes = bytes.fromhex(signature_hex[2:])
    signature = keys.Signature(signature_bytes)
    return public_key.verify_msg_hash(message_hash, signature)


# Proof handling
def sign_proof_object(private_key, proof_object):
    proof_str = str(proof_object).encode()
    proof_hash = compute_sha256(proof_str)
    signature = private_key.sign_msg_hash(proof_hash)
    return proof_hash.hex(), signature


def save_proof_and_signatures_json(filename, proof_object, signatureA, signatureB, public_key):
    data_to_save = {
        'proof_object': proof_object,
        'signatureA': str(signatureA),
        'signatureB': str(signatureB),
        'public_key': str(public_key)
    }
    with open(filename, 'w') as f:
        json.dump(data_to_save, f, indent=4)


def load_proof_and_signatures_json(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data['proof_object'], data['signatureA'], data['signatureB'], data['public_key']


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
            print('Automatic check failed. Precommitted values do not match. Please investigate.')
        
        if public_key_stored != str(public_key):
            print('Public keys do not match. Please check.')
    except FileNotFoundError:
        print("No automatic check performed. Please check manually.")
    except Exception as e:
        print(f"Error during automatic check: {e}")


def process_file_and_verify_roots(file_path, proof_roots, skip=10, rounding=5, full_verification=False, current_level=1):
    tree = MerkleTree(hash_type='sha256')
    level = 1
    with open(file_path, 'r') as f:
        for i, line in enumerate(f, start=1):
            if i % skip == 0:
                rounded_numbers = [round(float(num), rounding) for num in line.strip().split()]
                tree.append_entry(str(rounded_numbers).encode())
                if is_power_of_two(tree.get_size()):
                    root_hash = tree.get_state().hex()
                    if root_hash in proof_roots:
                        if level >= current_level:
                            print(f'Verification passed at level {level}')
                        level += 1
                    else:
                        print('Verification failed')
    if full_verification and not is_power_of_two(tree.get_size()):
        root_hash = tree.get_state().hex()
        if root_hash in proof_roots:
            print('Full verification passed')
        else:
            print('Verification failed')
    return level -1 


# Git and YAML handling
def get_commit_hash():
    try:
        commit_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).strip().decode('utf-8')
        return commit_hash
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def ordered_load(stream, Loader=yaml.SafeLoader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_dump(data, stream=None, Dumper=yaml.SafeDumper, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_dict(data.items())

    OrderedDumper.add_representer(OrderedDict, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


# File discovery and key removal
def find_specific_entries(data, file_extensions=('.txt', '.dat')):
    results = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                results.extend(find_specific_entries(value, file_extensions))
            elif isinstance(value, str) and value.endswith(file_extensions):
                results.append(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                results.extend(find_specific_entries(item, file_extensions))
            elif isinstance(item, str) and item.endswith(file_extensions):
                results.append(item)
    return results


def remove_keys_recursive(data, exclude_keys):
    if isinstance(data, dict):
        return {k: remove_keys_recursive(v, exclude_keys) for k, v in data.items() if k not in exclude_keys}
    return data


# Analysis functions
def compute_analysis_hash_old(input_path):
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
    exclude_keys = ["output", "likelihood", "seed"]
    filtered_input = remove_keys_recursive(copy.deepcopy(input_yaml), exclude_keys)
    input_hash = compute_sha256(str(filtered_input).encode()).hex()

    code_hashes = {}
    for theory in input_yaml['theory']:
        theorypath = f"../cobaya/theories/{theory}/{theory}"
        with open(f"{theorypath}.yaml", 'r') as file:
            theory_yaml = yaml.safe_load(file)

        package_origin = theory_yaml['path'] if theory_yaml['path'] else importlib.util.find_spec(theory).origin

        print(f"Found package {theory} at {package_origin}")

        if package_origin.endswith(('.so', '.pyd')):
            package_hash = compute_file_hash(package_origin)
        elif package_origin.endswith('__init__.py'):
            package_hash = compute_directory_hash(os.path.dirname(package_origin))
        else:
            print(f"Unsupported package type: {package_origin}")
            package_hash = '00000000dead'

        pycode_hash = compute_file_hash(f"{theorypath}.py")
        code_hashes[theory] = {'wrapper hash': pycode_hash, 'package hash': package_hash}

    pre_object = {'git_hash': git_hash, 'input_hash': input_hash, 'code_hashes': code_hashes}
    return pre_object, input_yaml



# Analysis functions
def compute_analysis_hash(input_path):
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
    exclude_keys = ["output", "likelihood", "seed"]
    filtered_input = remove_keys_recursive(copy.deepcopy(input_yaml), exclude_keys)
    input_hash = compute_sha256(str(filtered_input).encode()).hex()

    code_hashes = {}
    for theory in input_yaml['theory']:
        if theory == 'classy':
            theorypath = "/cosmo/code/classy/source"
        elif theory == 'CAMB':
            theorypath = '/cosmo/code/CAMB/fortran'
        else:
            print('theory not implemented yet. No verification')
            theorypath = f"cobaya/theories/{theory}/{theory}"

        package_hash = compute_directory_hash(os.path.dirname(theorypath))
        
        code_hashes[theory] = {'package hash': package_hash}

    pre_object = {'git_hash': git_hash, 'input_hash': input_hash, 'code_hashes': code_hashes}
    return pre_object, input_yaml


def compute_data_dict(input_yaml):
    data_dict = {'input_yaml_hash' : compute_sha256(str(input_yaml['likelihood']).encode()).hex()}
    for element in input_yaml['likelihood']:
        datapath = element.replace('.', '/')
        with open(f'cobaya/likelihoods/{datapath}.yaml', 'r') as file:
            data_yaml = yaml.safe_load(file)

        data_dict[element] = {'yaml_hash': compute_sha256(str(data_yaml).encode()).hex()}

        matches = find_specific_entries(data_yaml)
        for match in matches:
            match_hash = compute_file_hash(f'cosmo/data/{match}')
            data_dict[element][match] = match_hash

    return data_dict
