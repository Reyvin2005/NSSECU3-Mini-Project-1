import os
import binascii
import hashlib
import sys

class RuleGenerator:
    def __init__(self, source_folder, output_file="signatures.yar"):
        # Use raw string r"" to handle Windows backslashes correctly
        self.source_folder = source_folder
        self.output_file = output_file
        self.rules = []
        self.file_count = 0

    def calculate_md5(self, filepath):
        """Calculates the MD5 hash of the entire file for verification."""
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "ERROR"

    def determine_specific_file_type(self, header_bytes):
        """
        Forensic analysis of the first 50 bytes to determine specific file DNA.
        """
        if not header_bytes: return "EMPTY"
        hb = header_bytes
        h_str = hb.decode('latin-1', errors='ignore') 

        # 1. JPEG Analysis
        if hb.startswith(b'\xFF\xD8'):
            if b'\xFF\xE0' in hb[:12]: return "JPEG-JFIF"
            if b'\xFF\xE1' in hb[:12]: return "JPEG-EXIF"
            return "JPEG"

        # 2. PNG
        if hb.startswith(b'\x89PNG\r\n\x1a\n'): return "PNG"

        # 3. PDF (with version check)
        if hb.startswith(b'%PDF-'):
            try:
                ver = h_str[5:8] # Extracts "1.4", "1.7", etc.
                return f"PDF-{ver}" 
            except:
                return "PDF"

        # 4. EXE
        if hb.startswith(b'MZ'):
            if b'DOS mode' in hb: return "EXE-DOS"
            return "EXE"

        # 5. ZIP/Office
        if hb.startswith(b'PK\x03\x04'):
            if b'word/' in hb or b'[Content_Types].xml' in hb: return "DOCX"
            if b'xl/' in hb: return "XLSX"
            if b'ppt/' in hb: return "PPTX"
            return "ZIP"
        
        # 6. Others
        if hb.startswith(b'GIF87a'): return "GIF87a"
        if hb.startswith(b'GIF89a'): return "GIF89a"
        if hb.startswith(b'BM'): return "BMP"
        if hb.startswith(b'Rar!'): return "RAR"
        if hb.startswith(b'7z'): return "7Z"
        
        return "UNKNOWN"

    def generate_rules(self):
        print(f"[*] Analyzing files in: {self.source_folder}")
        
        if not os.path.exists(self.source_folder):
            print(f"[!] Error: Source folder '{self.source_folder}' not found.")
            return

        # Sort files to keep rule generation order consistent
        files = sorted(os.listdir(self.source_folder))
        
        for filename in files:
            file_path = os.path.join(self.source_folder, filename)
            
            if not os.path.isfile(file_path):
                continue

            try:
                # 1. Collect Metadata for "Walang Sobra" Verification
                file_size = os.path.getsize(file_path)
                file_md5 = self.calculate_md5(file_path)

                with open(file_path, 'rb') as f:
                    magic_bytes = f.read(50)
                    specific_type = self.determine_specific_file_type(magic_bytes)
                    
                    # Convert to Hex
                    hex_string = binascii.hexlify(magic_bytes).decode('utf-8').upper()
                    yara_hex = " ".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))

                    self.file_count += 1
                    
                    # Sanitize Rule Name (Replace dots and dashes with underscores)
                    safe_type = specific_type.replace('-', '_').replace('.', '_')
                    rule_name = f"rule_{self.file_count:03d}_{safe_type}"
                    
                    # --- STRICT YARA RULE ---
                    # The condition ONLY checks the 50 bytes (per prompt requirements).
                    # The Size and MD5 are stored in META for the Python scanner to verify.
                    rule = f"""
rule {rule_name} {{
    meta:
        original_name = "{filename}"
        file_type = "{specific_type}"
        target_size = {file_size}
        target_md5 = "{file_md5}"
    strings:
        $magic_bytes = {{ {yara_hex} }}
    condition:
        $magic_bytes at 0
}}"""
                    self.rules.append(rule)
                    print(f"    [+] Processed: {filename} -> {specific_type}")

            except Exception as e:
                print(f"    [!] Error processing {filename}: {str(e)}")

        self.save_rules()

    def save_rules(self):
        try:
            with open(self.output_file, 'w') as f:
                f.write("// NSSECU3 MP1 - Generated YARA Signatures\n")
                f.write(f"// Total Rules: {len(self.rules)}\n\n")
                f.write("\n".join(self.rules))
            print(f"\n[*] Success! Generated {len(self.rules)} rules in '{self.output_file}'")
        except IOError as e:
            print(f"[!] Error writing YARA file: {e}")

if __name__ == "__main__":
    # --- CONFIGURATION: POINT THIS TO YOUR FOLDER ---
    SOURCE_DIR = r"C:\Users\dlsud\Desktop\NSSECU3_MP1\source_files\File"
    
    generator = RuleGenerator(SOURCE_DIR)
    generator.generate_rules()