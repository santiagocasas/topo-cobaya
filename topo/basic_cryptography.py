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
import getpass

from basic_utility import load_json



# Utility functions
def compute_sha256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()


# Key management
def load_private_key(file_path):

    if file_path.endswith(".txt"):
        
        with open(file_path, "r") as f:
            private_key_hex = f.read()
        return keys.PrivateKey(bytes.fromhex(private_key_hex[2:]))
    
    else:
        with open(file_path, 'r') as f:
            encrypted_key = json.load(f)

        password = getpass.getpass("Please enter the password to decrypt the private key: ")
        try:
            decrypted_private_key = Account.decrypt(encrypted_key, password)
            print("Decryption successful.")
            return keys.PrivateKey(decrypted_private_key)
    
        except ValueError:
            print("Incorrect password or failed to decrypt the key.")
            sys.exit(1)



def save_private_key(private_key):

    os.makedirs("topo/cryptoFiles", exist_ok=True)
        

    user_input = input("Do you want to store your key encrypted? (yes/no): ").strip().lower()
    if user_input == 'yes':
        password = getpass.getpass("Please enter password: ")
        password2 = getpass.getpass("Reenter password: ")
        if password == password2: 
        
            encrypted_key = Account.encrypt(private_key, password)
            key_path = "topo/cryptoFiles/encrypted_key.json"

            base, extension = os.path.splitext(key_path)
            counter = 1
        
            # Keep adding a number to the base name until a unique path is found
            while os.path.exists(f"{base}_{counter}{extension}"):
                counter += 1 

            key_path = f"{base}_{counter}{extension}"

            with open(key_path, "w") as f:
                json.dump(encrypted_key, f)
            print(f"Encrypted key saved to {key_path}")
        else: 
            print("Passwords dont match")
            sys.exit(1)


        
    else: # store in plain .txt
    
        key_path = "topo/cryptoFiles/private_key.txt"
        base, extension = os.path.splitext(key_path)
        counter = 1
    
        # Keep adding a number to the base name until a unique path is found
        while os.path.exists(f"{base}_{counter}{extension}"):
            counter += 1 

        key_path = f"{base}_{counter}{extension}"

        with open(key_path, "w") as f:
            f.write(str(private_key.to_hex()))
        print(f"Keys generated and saved to {key_path}.")
    
    params = load_json('topo/params.json')
    params['key_path'] = key_path
    #print(params)
    with open('topo/params.json', 'w') as f:
        json.dump(params, f, indent=4)
    
  

def generate_keys():
    private_key_bytes = os.urandom(32)
    private_key = keys.PrivateKey(private_key_bytes)

    return private_key



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



# Git and YAML handling
def get_commit_hash():
    try:
        commit_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).strip().decode('utf-8')
        return commit_hash
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def get_commit_hash_from_path(repo_path):
    """
    Get the latest git commit hash from the given repository path.
    """
    try:
        # Check if the path is a valid git repository
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            print(f"The directory {repo_path} is not a valid git repository.")
            return None
        
        # Run the git command to get the latest commit hash
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_path).strip().decode("utf-8")
        return commit_hash
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


