#!/usr/bin/env python3
import os
import hashlib
import argparse
from shutil import move

# Constants extracted from moo.c
MOO_SIGNATURES = {
    'function_names': [
        b'moo_starter',
        b'moo_open_and_read_file',
        b'moo_operation_encrypt'
    ],
    'constants': [
        b'MOO_ENCRYPTION_KEY',
        b'MOO_PADDER',
        b'MOO_ERROR_FILE_READ_ERROR'
    ]
}

def calculate_hashes(filepath):
    """Calculate multiple cryptographic hashes for identification"""
    hash_algorithms = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for h in hash_algorithms.values():
                h.update(chunk)
    
    return {k: v.hexdigest() for k, v in hash_algorithms.items()}

def is_moo_binary(filepath):
    """Check if file matches moo's characteristics using multiple heuristics"""
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
            # Check for multiple signatures to reduce false positives
            signature_matches = sum(
                1 for sig_list in MOO_SIGNATURES.values()
                for sig in sig_list
                if sig in content
            )
            
            # Minimum threshold of matches required
            return signature_matches >= 3
    except Exception as e:
        print(f"Error analyzing {filepath}: {str(e)}")
        return False

def quarantine_file(filepath, quarantine_dir='/var/quarantine/moo'):
    """Safely quarantine detected malware"""
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        target_path = os.path.join(quarantine_dir, filename)
        
        # Handle name collisions
        counter = 1
        while os.path.exists(target_path):
            name, ext = os.path.splitext(filename)
            target_path = os.path.join(quarantine_dir, f"{name}_{counter}{ext}")
            counter += 1
        
        move(filepath, target_path)
        print(f"Quarantined: {filepath} -> {target_path}")
        return True
    except Exception as e:
        print(f"Failed to quarantine {filepath}: {str(e)}")
        return False

def scan_system(path, action='report', recursive=True):
    """Comprehensive scanning with detailed reporting"""
    scan_results = {
        'scanned': 0,
        'detected': 0,
        'quarantined': 0,
        'errors': 0
    }
    
    walker = os.walk(path) if recursive else [(path, [], os.listdir(path))]
    
    for root, _, files in walker:
        for file in files:
            filepath = os.path.join(root, file)
            scan_results['scanned'] += 1
            
            try:
                if is_moo_binary(filepath):
                    scan_results['detected'] += 1
                    print(f"Detected: {filepath}")
                    
                    if action == 'quarantine':
                        if quarantine_file(filepath):
                            scan_results['quarantined'] += 1
            except Exception as e:
                scan_results['errors'] += 1
                print(f"Error processing {filepath}: {str(e)}")
    
    print("\nScan Summary:")
    print(f"Files scanned: {scan_results['scanned']}")
    print(f"Detected: {scan_results['detected']}")
    if action == 'quarantine':
        print(f"Quarantined: {scan_results['quarantined']}")
    print(f"Errors: {scan_results['errors']}")
    
    return scan_results
