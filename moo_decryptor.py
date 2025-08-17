#!/usr/bin/env python3
import os
import argparse
import magic  # python-magic package
from typing import Optional, Tuple

# Exact parameters from moo.c
MOO_ENCRYPTION_KEY = 0xff
MOO_PADDER = 0x04

class MooDecryptor:
    def __init__(self):
        self.file_identifier = magic.Magic(mime=True)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Reverse the exact encryption algorithm from moo.c"""
        return bytes([((b ^ MOO_ENCRYPTION_KEY) - MOO_PADDER) & 0xff for b in encrypted_data])
    
    def is_encrypted(self, filepath: str) -> Tuple[bool, Optional[str]]:
        """Check if file is likely encrypted by moo"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024)  # Only check first KB for efficiency
            
            if not data:
                return False, "Empty file"
            
            # Check for non-printable bytes
            if all(b < 128 and b >= 32 for b in data[:100]):
                return False, "Appears to be plain text"
            
            # Attempt partial decryption
            decrypted = self.decrypt_data(data[:100])
            
            # Check if decrypted data makes sense
            if any(32 <= b < 127 for b in decrypted):
                return True, "High probability of moo encryption"
            return False, "Doesn't match moo encryption pattern"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def decrypt_file(self, input_path: str, output_path: str) -> bool:
        """Full file decryption with validation"""
        try:
            with open(input_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = self.decrypt_data(encrypted)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            # Verify decryption
            if self.is_encrypted(output_path)[0]:
                os.remove(output_path)
                raise ValueError("Decryption failed - output still appears encrypted")
            
            return True
        except Exception as e:
            print(f"Failed to decrypt {input_path}: {str(e)}")
            return False
    
    def batch_decrypt(self, input_dir: str, output_dir: str) -> dict:
        """Process directory with comprehensive reporting"""
        results = {
            'processed': 0,
            'success': 0,
            'skipped': 0,
            'errors': 0
        }
        
        os.makedirs(output_dir, exist_ok=True)
        
        for filename in os.listdir(input_dir):
            input_path = os.path.join(input_dir, filename)
            output_path = os.path.join(output_dir, f"decrypted_{filename}")
            
            try:
                if not os.path.isfile(input_path):
                    continue
                
                results['processed'] += 1
                
                is_enc, reason = self.is_encrypted(input_path)
                if not is_enc:
                    print(f"Skipping {filename}: {reason}")
                    results['skipped'] += 1
                    continue
                
                if self.decrypt_file(input_path, output_path):
                    results['success'] += 1
                    print(f"Successfully decrypted: {filename}")
                else:
                    results['errors'] += 1
            except Exception as e:
                results['errors'] += 1
                print(f"Error processing {filename}: {str(e)}")
        
        return results
