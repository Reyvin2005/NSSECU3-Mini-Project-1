#!/usr/bin/env python3
"""
rule_generator.py
Generates a single YARA file (signatures.yar) with wildcard-based rules
grouped by file type. Uses the first up to 50 bytes of each file.
"""

import os
import hashlib
import math
from collections import defaultdict

# ----------------------------------------------------------------------
# 3-Tier File Type Detection
# ----------------------------------------------------------------------
def detect_file_type(first_n_bytes):
    """Determine file type based on standard signatures and content analysis."""
    # Standard signatures (first few bytes)
    if first_n_bytes.startswith(b'\xFF\xD8\xFF\xE0'):
        if first_n_bytes[6:10] == b'JFIF':
            return 'JPEG-JFIF'
        elif first_n_bytes[6:10] == b'EXIF':
            return 'JPEG-EXIF'
        else:
            return 'JPEG-APP0'
    elif first_n_bytes.startswith(b'\xFF\xD8\xFF\xE1'):
        return 'JPEG-APP1'
    elif first_n_bytes.startswith(b'\xFF\xD8\xFF'):
        return 'JPEG'
    elif first_n_bytes.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        if len(first_n_bytes) >= 16 and first_n_bytes[12:16] == b'IHDR':
            return 'PNG'
        else:
            return 'MODIFIED-PNG'
    elif first_n_bytes.startswith(b'\x25\x50\x44\x46\x2D'):
        version = first_n_bytes[5:8].decode('ascii', errors='ignore')
        if version.startswith('1.'):
            return f'PDF-{version}'
        else:
            return 'PDF'
    elif first_n_bytes.startswith(b'\x4D\x5A'):
        return 'EXE'
    elif first_n_bytes.startswith(b'\x50\x4B\x03\x04'):
        return 'ZIP'
    elif first_n_bytes.startswith(b'\xEF\xBB\xBF'):
        return 'UTF8-TEXT'
    elif first_n_bytes.startswith(b'\x40\x65\x63\x68\x6F\x20') or first_n_bytes.startswith(b'@echo '):
        return 'BATCH'
    elif first_n_bytes.startswith(b'\x49\x44\x33'):
        return 'ID3'
    elif first_n_bytes.startswith(b'\x52\x49\x46\x46'):
        return 'RIFF'
    else:
        return analyze_content(first_n_bytes)

def analyze_content(data):
    """Analyze byte content to classify unknown files."""
    if not data:
        return 'CUSTOM-EMPTY'
    null_ratio = data.count(0) / len(data)
    printable = sum(1 for b in data if 32 <= b <= 126) / len(data)
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values()) if data else 0
    if null_ratio > 0.8:
        return 'CUSTOM-NULLPAD'
    elif entropy > 7.5:
        return 'CUSTOM-HIGHENT'
    elif printable > 0.9:
        return 'CUSTOM-ASCIIDOM'
    else:
        return 'CUSTOM-UNKNOWN-BIN'

# ----------------------------------------------------------------------
# Wildcard pattern generation (handles variable lengths)
# ----------------------------------------------------------------------
def generate_wildcard_pattern(byte_sequences):
    """
    Given a list of byte sequences (possibly of different lengths),
    generate a hex string with '??' for positions that vary.
    The pattern length is the minimum length among all sequences.
    """
    if not byte_sequences:
        return ''
    min_len = min(len(seq) for seq in byte_sequences)
    pattern_bytes = []
    for i in range(min_len):
        bytes_at_i = [seq[i] for seq in byte_sequences]
        if all(b == bytes_at_i[0] for b in bytes_at_i):
            pattern_bytes.append(bytes_at_i[0])
        else:
            pattern_bytes.append(None)
    hex_parts = ['??' if b is None else f'{b:02X}' for b in pattern_bytes]
    return ' '.join(hex_parts)

# ----------------------------------------------------------------------
# Main generator
# ----------------------------------------------------------------------
def generate_yara_rules(file_paths, output_file='signatures.yar'):
    groups = defaultdict(list)
    hash_data = {}
    for path in file_paths:
        try:
            with open(path, 'rb') as f:
                first_n = f.read(50)          # read up to 50 bytes
                # Compute full file hashes
                f.seek(0)
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                size = 0
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    size += len(chunk)
                md5_digest = md5.hexdigest().upper()
                sha1_digest = sha1.hexdigest().upper()
                file_type = detect_file_type(first_n)
                groups[file_type].append((first_n, path))
                hash_data[md5_digest] = {
                    'sha1': sha1_digest,
                    'file_type': file_type,
                    'file_size': size
                }
                print(f"Processed {path} -> {file_type} (len={len(first_n)})")
        except Exception as e:
            print(f"Error processing {path}: {e}")
    # Write YARA rules
    with open(output_file, 'w') as yara_out:
        yara_out.write('// Generated by rule_generator.py\n')
        yara_out.write('// Hybrid wildcard + hash verification rules\n\n')
        for file_type, files in groups.items():
            if not files:
                continue
            rule_name = file_type.replace('-', '_').replace('.', '_') + '_Group'
            yara_out.write(f'rule {rule_name} {{\n')
            yara_out.write('    meta:\n')
            yara_out.write(f'        file_type = "{file_type}"\n')
            yara_out.write(f'        total_files_in_group = "{len(files)}"\n')
            yara_out.write('        detection_method = "HYBRID_WILDCARD_AND_HASH"\n')
            yara_out.write('        requires_hash_verification = "true"\n')
            yara_out.write('    strings:\n')
            pattern = generate_wildcard_pattern([b for b, _ in files])
            if pattern:
                yara_out.write(f'        $header = {{ {pattern} }}\n')
            else:
                yara_out.write(f'        $header = {{ }}\n')
            yara_out.write('    condition:\n')
            yara_out.write('        $header at 0\n')
            yara_out.write('}\n\n')
    return hash_data

# ----------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: rule_generator.py <directory_with_220_files>")
        sys.exit(1)
    root_dir = sys.argv[1]
    all_files = []
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            all_files.append(os.path.join(root, f))
    print(f"Found {len(all_files)} files to process")
    hash_data = generate_yara_rules(all_files, 'signatures.yar')
    with open('verification_data.py', 'w') as vf:
        vf.write('# Auto-generated verification data\n')
        vf.write('verification_data = {\n')
        for md5, info in sorted(hash_data.items()):
            vf.write(f"    '{md5}': {info},\n")
        vf.write('}\n')
    print(f"\nGenerated signatures.yar with {len(set(info['file_type'] for info in hash_data.values()))} rule groups")
    print(f"Generated verification_data.py with {len(hash_data)} hash entries")