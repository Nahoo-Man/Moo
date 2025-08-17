#!/usr/bin/env python3
import argparse
from moo_detector import scan_system
from moo_decryptor import MooDecryptor

def main():
    parser = argparse.ArgumentParser(
        description="Moo Malware Toolkit - Comprehensive Detection and Recovery",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Detect moo malware')
    scan_parser.add_argument('path', help='Directory to scan')
    scan_parser.add_argument('--quarantine', action='store_true', 
                           help='Automatically quarantine detected files')
    scan_parser.add_argument('--no-recursive', action='store_true',
                           help='Disable recursive directory scanning')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt moo-encrypted files')
    decrypt_parser.add_argument('input', help='Input file or directory')
    decrypt_parser.add_argument('output', help='Output file or directory')
    decrypt_parser.add_argument('--force', action='store_true',
                              help='Attempt decryption even if detection is uncertain')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scan_system(
            path=args.path,
            action='quarantine' if args.quarantine else 'report',
            recursive=not args.no_recursive
        )
    elif args.command == 'decrypt':
        decryptor = MooDecryptor()
        
        if os.path.isfile(args.input):
            if decryptor.decrypt_file(args.input, args.output):
                print(f"Successfully decrypted to {args.output}")
        elif os.path.isdir(args.input):
            results = decryptor.batch_decrypt(args.input, args.output)
            print("\nDecryption Summary:")
            print(f"Files processed: {results['processed']}")
            print(f"Successfully decrypted: {results['success']}")
            print(f"Skipped: {results['skipped']}")
            print(f"Errors: {results['errors']}")
        else:
            print("Error: Invalid input path")

if __name__ == "__main__":
    main()
