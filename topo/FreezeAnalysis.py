from eth_account import Account
from utils import (
    load_private_key, compute_sha256,  
    compute_analysis_hash,
    sign_proof_object,  
    save_proof_and_signatures_json
)
import sys 

if __name__ == "__main__":
    """
    Main function to orchestrate the hash generation and display the analysis information.
    """

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

    # Generate account from private key (Ethereum address)
    account = Account.from_key(private_key)

    # Compute analysis hash and sign the pre-object
    pre_object, _ = compute_analysis_hash(input_path)
    pre_hash, signature = sign_proof_object(private_key, pre_object)

    # Verify the signature
    message_hash = compute_sha256(str(pre_object).encode())
    is_valid = public_key.verify_msg_hash(message_hash, signature)

    print("\nInformation to publish with timestamp:")
    print(f"Analysis hash: {pre_hash}")
    print(f"Signature: {signature}")
    print(f"Testing Signature: {is_valid}")

    print("\nIf not known publicly yet: publish")
    print(f"Public Key: {public_key}")
    print(f"Ethereum Address: {account.address}")

    print("Please keep corresponding private key safe")

    print("\nPublish now, or later if code is still secret")
    print(f"The input file, and the git branch including the versions of installed theory codes")
    print(f"Those should match these hashes {pre_object}")

    # Save the pre-object and signatures to a JSON file
    save_proof_and_signatures_json(f'pre_object_{pre_hash[:6]}.json', pre_object, signature, None, public_key)
    print('Pre-object saved in JSON')




