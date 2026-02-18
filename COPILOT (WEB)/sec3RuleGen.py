import os
import hashlib
import binascii
import json
import math

# ---------- File Type Detection (3-Tier) ----------
def detect_standard_signatures(first_50_bytes):
    signatures = {
        b"\xFF\xD8\xFF\xE0": "JPEG_JFIF",
        b"\xFF\xD8\xFF\xE1": "JPEG_EXIF",
        b"\x89PNG": "PNG",
        b"GIF87a": "GIF87a",
        b"GIF89a": "GIF89a",
        b"%PDF-": "PDF",
        b"PK\x03\x04": "ZIP",
        b"MZ": "EXE",
    }
    for sig, ftype in signatures.items():
        if first_50_bytes.startswith(sig):
            return ftype
    return "UNKNOWN"

def analyze_patterns(first_50_bytes):
    if first_50_bytes.count(b"\x00") > 20:
        return "CUSTOM_NULLPAD"
    return "UNKNOWN"

def analyze_characteristics(first_50_bytes):
    freq = [first_50_bytes.count(bytes([b]))/50 for b in set(first_50_bytes)]
    entropy = -sum(p * math.log(p, 2) for p in freq if p > 0)
    if entropy > 7.5:
        return "CUSTOM_HIGHENT"
    return "CUSTOM_UNKNOWN_BIN"

def determine_file_type(first_50_bytes):
    ftype = detect_standard_signatures(first_50_bytes)
    if ftype != "UNKNOWN":
        return ftype, "STANDARD_SIGNATURE"
    ftype = analyze_patterns(first_50_bytes)
    if ftype != "UNKNOWN":
        return ftype, "PATTERN_ANALYSIS"
    # ✅ Always assign a label, never skip
    return analyze_characteristics(first_50_bytes), "CONTENT_ANALYSIS"

# ---------- Hash Calculation ----------
def calculate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
    return hash_md5.hexdigest(), hash_sha1.hexdigest()

# ---------- Rule Generator ----------
def generate_rules(input_folder, yara_output, json_output):
    rules = []
    verification_data = []
    index = 1

    for fname in os.listdir(input_folder):
        fpath = os.path.join(input_folder, fname)
        if not os.path.isfile(fpath):
            continue

        with open(fpath, 'rb') as f:
            first_50 = f.read(50)

        file_type, detection_method = determine_file_type(first_50)
        md5, sha1 = calculate_file_hashes(fpath)
        fsize = os.path.getsize(fpath)
        md5_prefix = md5[:8]

        safe_file_type = file_type.replace("-", "_")
        rule_name = f"rule_{index:03d}_{safe_file_type}_{md5_prefix}"
        hex_bytes = binascii.hexlify(first_50).decode().upper()
        hex_formatted = " ".join([hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)])

        rule = f"""
rule {rule_name} {{
    meta:
        original_name = "{fname}"
        file_type = "{file_type}"
        file_size = {fsize}
        original_md5 = "{md5}"
        original_sha1 = "{sha1}"
        id = "{index:03d}"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = {{ {hex_formatted} }}

    condition:
        $magic_bytes at 0
}}
"""
        rules.append(rule)

        verification_data.append({
            "id": f"{index:03d}",
            "original_name": fname,
            "file_type": file_type,
            "file_size": fsize,
            "md5": md5,
            "sha1": sha1,
            "first_50_bytes_hex": hex_bytes
        })

        index += 1

    with open(yara_output, "w") as f:
        f.write("\n".join(rules))

    with open(json_output, "w") as f:
        json.dump(verification_data, f, indent=2)

if __name__ == "__main__":
    generate_rules(r"E:\Users\dchoi\Documents\File", "signatures.yar", "file_verification_data.json")
