#!/usr/bin/env python3
import argparse
import sys
import os
from topo import __version__ as topo_version
from topo.FreezeAnalysis import main as freeze_main
from topo.GenerateProof import main as proof_main
from topo.Keygen import main as keygen_main
from topo.Verify import main as verify_main

def main():
    parser = argparse.ArgumentParser(description="Topo-Cobaya CLI")
    parser.add_argument('--version', action='version', version=f'Topo-Cobaya {topo_version}')
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Keygen command
    keygen_parser = subparsers.add_parser("keygen", help="Generate or load keys")
    keygen_parser.add_argument("--load", metavar="KEY_PATH", help="Load an existing private key from the specified path")

    # Freeze command
    freeze_parser = subparsers.add_parser("freeze", help="Freeze analysis")
    freeze_group = freeze_parser.add_mutually_exclusive_group(required=True)
    freeze_group.add_argument("input_path", nargs="?", help="Path to the cobaya input file for analysis")
    freeze_group.add_argument("-p", "--path", help="Alternative way to specify the path to the cobaya input file")

    # Proof command
    proof_parser = subparsers.add_parser("proof", help="Generate proof")
    proof_group = proof_parser.add_mutually_exclusive_group(required=True)
    proof_group.add_argument("input_path", nargs="?", help="Path to the input file")
    proof_group.add_argument("-p", "--path", help="Alternative way to specify the path to the input file")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify Topo-Cobaya analysis")
    verify_group = verify_parser.add_mutually_exclusive_group(required=True)
    verify_group.add_argument("input_path", nargs="?", help="Path to the input file")
    verify_group.add_argument("-p", "--path", help="Alternative way to specify the path to the input file")
    verify_parser.add_argument("extra_args", nargs="*", help="Extra arguments for verification")

    args = parser.parse_args()

    if args.command == "freeze":
        if args.path:
            args.input_path = args.path
        freeze_main(args)
    elif args.command == "proof":
        if args.path:
            args.input_path = args.path
        proof_main(args)
    elif args.command == "keygen":
        keygen_main(args)
    elif args.command == "verify":
        if args.path:
            args.input_path = args.path
        verify_main(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
