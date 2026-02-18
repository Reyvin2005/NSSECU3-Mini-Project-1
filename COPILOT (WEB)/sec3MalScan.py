import os
import yara
import hashlib
import csv
import json
import sys
import time

# ---------- Hash Calculation ----------
def calculate_file_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
    return hash_md5.hexdigest(), hash_sha1.hexdigest()

# ---------- Load Verification Data ----------
def load_verification_data(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)
    md5_lookup = {item["md5"]: item for item in data}
    return data, md5_lookup

# ---------- Count Files for Estimate ----------
def count_files(drives):
    total = 0
    for drive in drives:
        for _, _, files in os.walk(drive, topdown=True):
            total += len(files)
    return total

# ---------- Scanner ----------
def scan_drive(drive, rules, md5_lookup, writer, progress, total_files, targets_found):
    scanned = progress[0]
    for root, dirs, files in os.walk(drive, topdown=True):
        for fname in files:
            fpath = os.path.join(root, fname)
            scanned += 1
            try:
                with open(fpath, 'rb') as f:
                    first_50 = f.read(50)
                matches = rules.match(data=first_50)
                if matches:
                    md5, sha1 = calculate_file_hashes(fpath)
                    # ✅ Only write verified matches (MD5 + SHA1)
                    if md5 in md5_lookup and md5_lookup[md5]["sha1"] == sha1:
                        item = md5_lookup[md5]
                        writer.writerow([
                            fname,
                            md5,
                            sha1,
                            fpath,
                            item["file_type"],
                            item["first_50_bytes_hex"]
                        ])
                        targets_found[0] += 1
                # Progress indicator
                percent = (scanned / total_files) * 100
                print(f"\rScanning {drive}: {percent:.2f}% complete ({scanned}/{total_files} files) | Targets found: {targets_found[0]}", end="")
            except PermissionError:
                continue
            except Exception:
                continue
    progress[0] = scanned

def main():
    try:
        start_time = time.time()
        rules = yara.compile(filepath="signatures.yar")
        data, md5_lookup = load_verification_data("file_verification_data.json")

        # Detect all drives automatically
        all_drives = [f"{chr(d)}:\\" for d in range(ord('C'), ord('Z')+1) if os.path.exists(f"{chr(d)}:\\")]

        # Drives to skip (customize here)
        #skip_drives = ["C:\\"]  # Example: skip system drives, ex ["C:\\", "D:\\"]

        # Final drive list = all drives except skipped ones
        drives = [d for d in all_drives if d not in skip_drives]

        total_files = count_files(drives)
        print(f"Total files to scan: {total_files}")
        print("Estimated time: ~{:.1f} seconds".format(total_files * 0.01))  # rough estimate

        with open("MP1_Scan_Results.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["File Name","Hash MD5","Hash SHA1","Directory","File Type","Magic Bytes"])

            progress = [0]
            targets_found = [0]

            for drive in drives:
                print(f"\nScanning drive {drive}...")
                scan_drive(drive, rules, md5_lookup, writer, progress, total_files, targets_found)

        elapsed = time.time() - start_time
        print(f"\n\nScan Finished!")
        print(f"Targets Found: {targets_found[0]}")
        print(f"Time Elapsed: {elapsed:.2f} seconds")

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()

