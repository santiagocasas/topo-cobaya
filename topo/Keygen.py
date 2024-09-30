from basic_cryptography import generate_keys, save_private_key, load_private_key
from basic_utility import load_json

from eth_keys import keys
from eth_account import Account
import sys
import json


# Run this to generate some keys

if __name__ == "__main__":

# Ask the user if they already have a private key
    user_input = input("Do you wish to load an existing key? (yes/no): ").strip().lower()

    if user_input == 'yes':
        # Load an existing private key
        key_path = input("Please provide the path to your private key file: ").strip()
        
        try:
            private_key = load_private_key(key_path)
            params = load_json('topo/params.json')
            params['key_path'] = key_path
            with open('topo/params.json', 'w') as f:
                json.dump(params, f, indent=4)
    
            
        except FileNotFoundError:
            print(f"Error: The private key file '{key_path}' was not found.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while loading the private key: {e}")
            sys.exit(1)

        
    
    elif user_input == 'no':
        # Generate a new private key
        print("Generating a new private key...")
        private_key = generate_keys()
        save_private_key( private_key)


    else:
        print("Invalid input. Please enter 'yes' or 'no'.")
        sys.exit(1)

    # Derive the public key and Ethereum account from the private key
    public_key = private_key.public_key
    account = Account.from_key(private_key)

    # Output the public key and Ethereum address
    print("\nIf not known publicly yet: publish")
    print(f"Public Key: {public_key}")
    print(f"Ethereum Address: {account.address}")

    print("Please keep the corresponding private key safe.")