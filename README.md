
# Moo Malware Toolkit

A comprehensive cybersecurity toolkit for detecting and decrypting files affected by the "moo" XOR-based file encryptor.

![Cybersecurity Shield Icon](https://img.icons8.com/color/96/000000/security-checked.png)

## Features

- **Precision Detection**:
  - Multi-signature scanning (MD5, SHA1, SHA256)
  - Heuristic binary analysis
  - Recursive directory scanning
  - Safe quarantine functionality

- **Accurate Decryption**:
  - Exact reversal of moo's encryption algorithm:
    ```python
    ((byte ^ 0xFF) - 0x04) & 0xFF
    ```
  - Batch file processing
  - Automatic encryption detection

- **Enterprise Ready**:
  - Detailed operation reporting
  - Comprehensive error handling
  - Memory-safe operations

## Technical Implementation

### Core Algorithm
Reverses moo.c's encryption precisely:
```c
// Original encryption in moo.c:
data = (data + MOO_PADDER) ^ MOO_ENCRYPTION_KEY;

// Python decryption:
decrypted = ((b ^ 0xFF) - 0x04) & 0xFF
Key Components
Component	Purpose	Key Feature
Scanner	Detect moo binaries	Signature + heuristic analysis
Decryptor	Recover encrypted files	Bit-perfect decryption
Quarantine	Isolate malware	Safe file handling
Installation
bash
# Clone repository
https://github.com/Nahoo-Man/Moo-Malware-Toolkit-main.git
cd moo-toolkit

# Install dependencies
pip install -r requirements.txt

# Install system dependencies (Debian/Ubuntu)
sudo apt-get install libmagic1
Usage
Basic Scanning
bash
# Scan directory (report only)
python moo_toolkit.py scan /path/to/scan

# Scan and quarantine
python moo_toolkit.py scan /path --quarantine
File Recovery
bash
# Decrypt single file
python moo_toolkit.py decrypt infected.doc clean.doc

# Batch decrypt directory
python moo_toolkit.py decrypt /infected /clean --force
Command Reference
Command	Options	Description
scan	--quarantine, --no-recursive	Detect moo binaries
decrypt	--output, --force	Recover encrypted files
Technical Highlights
Mathematically Precise:

Implements exact inverse of moo's:

python
((b ^ 0xFF) - 0x04) & 0xFF
Efficient Detection:

python
def is_moo_binary(filepath):
    return any(
        sig in content 
        for sig_list in MOO_SIGNATURES.values() 
        for sig in sig_list
    )
Safe Recovery:

Validates decryption results

Preserves file integrity

License
Released under UNLICENSE - Same as original moo program

