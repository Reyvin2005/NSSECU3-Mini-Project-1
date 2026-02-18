import yara
import os
import csv
import string
import re
from collections import defaultdict

# Match only File001–File999
pattern = re.compile(r"^File\d{3}$")

# Compile YARA rules
rules = yara.compile(filepath="types.yar")

output_csv = "scan_results_app_v2.csv"
results = []

# Counters
rule_counts = defaultdict(int)
total_matched = 0
unknown_count = 0

# Custom order for grouping in CSV
order = {
    "PDF": 1,
    "PNG": 2,
    "JPEG": 3,
    "ZIP": 4,
    "MP3": 5,
    "EXE": 6,
    "RIFF": 7,
    "PS_I_UTF8": 8,
    "BAT": 9,
    "CD00": 10,
    "TXT_ASCII": 11,
    "TXT_UTF16": 12,
    "ISO": 13,
    "Unknown": 99
}

# 1️⃣ Get All Mounted Drives
def get_all_drives():
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\" 
        if os.path.exists(drive):
            drives.append(drive)
    return drives

# 2️⃣ Read First 50 Bytes
def get_magic_bytes(file_path, size=50):
    try:
        with open(file_path, "rb") as f:
            data = f.read(size)
            return data.hex()
    except:
        return "Unreadable"

# 3️⃣ Scan Drives Recursively
for drive in get_all_drives():
    print(f"Scanning drive: {drive}")

    for root, dirs, files in os.walk(drive):
        for filename in files:

            # Only File### pattern
            if not pattern.match(filename):
                continue

            name, ext = os.path.splitext(filename)

            # Only files WITHOUT extension
            if ext != "":
                continue

            file_path = os.path.join(root, filename)

            try:
                matches = rules.match(file_path)

                if matches:
                    detected_ext = matches[0].rule
                    magic_hex = get_magic_bytes(file_path)

                    results.append([
                        filename,
                        detected_ext,
                        file_path,
                        magic_hex
                    ])

                    rule_counts[detected_ext] += 1
                    total_matched += 1

                else:
                    magic_hex = get_magic_bytes(file_path)

                    results.append([
                        filename,
                        "Unknown",
                        file_path,
                        magic_hex
                    ])

                    unknown_count += 1

            except:
                continue  # Skip permission errors

# 4️⃣ Sort results by custom order
results.sort(key=lambda x: order.get(x[1], 100))

# 5️⃣ Save CSV
with open(output_csv, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([
        "File Name",
        "Detected Extension",
        "Full Path",
        "Magic Bytes (First 50 Bytes - Hex)"
    ])
    writer.writerows(results)

print("\nScan complete. Results saved to", output_csv)

# 6️⃣ Print Summary
print("\n===== Detection Summary =====")
for rule_name in sorted(rule_counts, key=lambda x: order.get(x, 100)):
    print(f"{rule_name}: {rule_counts[rule_name]}")

print(f"\nTotal matched files: {total_matched}")
print(f"Unknown files: {unknown_count}")
