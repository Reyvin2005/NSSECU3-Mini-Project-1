
rule rule_001_EXE_7d0690a2 {
    meta:
        original_name = "File001"
        file_type = "EXE"
        file_size = 10768
        original_md5 = "7d0690a235298519fdc912928f0333ef"
        original_sha1 = "d2affe98fcb0a0c473ca5756c3687a246b642bb3"
        id = "001"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_002_CUSTOM_UNKNOWN_BIN_e2142a94 {
    meta:
        original_name = "File002"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 556
        original_md5 = "e2142a946eca0ac74dd03fa1d9c67bd2"
        original_sha1 = "199a95428a251a9ffddfa209706016766b48087b"
        id = "002"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 5A 6F 6F 6D 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 73 20 }

    condition:
        $magic_bytes at 0
}


rule rule_003_CUSTOM_UNKNOWN_BIN_821094b7 {
    meta:
        original_name = "File003"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1855
        original_md5 = "821094b7f221d9b915bbc55bc9530a1c"
        original_sha1 = "2368cdb34d96a5c5c38884ed8d125ca9832107fd"
        id = "003"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A 54 68 65 20 55 6E 69 76 65 72 73 61 6C 20 50 }

    condition:
        $magic_bytes at 0
}


rule rule_004_CUSTOM_UNKNOWN_BIN_6d30132c {
    meta:
        original_name = "File004"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 149
        original_md5 = "6d30132c09d8e7feb13cd0fc951b8c67"
        original_sha1 = "a2e190b5a8609eb9f75095806f73d00add3e20e7"
        id = "004"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6C 69 6E 65 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 35 20 2B 20 31 0D 0A 66 6F 72 20 2F 66 20 22 }

    condition:
        $magic_bytes at 0
}


rule rule_005_EXE_8af314b5 {
    meta:
        original_name = "File005"
        file_type = "EXE"
        file_size = 2560
        original_md5 = "8af314b532681aa2a272543e89bc1eeb"
        original_sha1 = "7e68dba9fa672d5ede7e787e5c568a4ff2a789c0"
        id = "005"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_006_ZIP_17bbcf87 {
    meta:
        original_name = "File006"
        file_type = "ZIP"
        file_size = 4319474
        original_md5 = "17bbcf874c7ef4315dc7114f020c46e6"
        original_sha1 = "7133fe4d816c890e44c4c78b58a6c8681ac874b0"
        id = "006"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 11 02 00 00 11 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_007_ZIP_9184f89a {
    meta:
        original_name = "File007"
        file_type = "ZIP"
        file_size = 1013332
        original_md5 = "9184f89abe4a76d7a312312396473c2c"
        original_sha1 = "44e9c9a846f09707c247e4d4d4a3087c8574b4f1"
        id = "007"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 D4 A2 46 3F D9 01 00 00 EC 09 00 00 13 00 D3 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_008_PNG_75c7e160 {
    meta:
        original_name = "File008"
        file_type = "PNG"
        file_size = 1617304
        original_md5 = "75c7e160e5e35d778df5907c2c94dbd0"
        original_sha1 = "8a8b3c46ff4cb34085de75c055c43f3cc043cc1c"
        id = "008"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 4C 45 4E 5A 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 79 9C 6D D9 75 }

    condition:
        $magic_bytes at 0
}


rule rule_009_PNG_dcff3b11 {
    meta:
        original_name = "File009"
        file_type = "PNG"
        file_size = 1726586
        original_md5 = "dcff3b11da469dab3029d65b9a9a026d"
        original_sha1 = "08c81c41b9bba9ec78f908a770a2144ddca93ab3"
        id = "009"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 93 24 39 92 }

    condition:
        $magic_bytes at 0
}


rule rule_010_ZIP_df23a5f6 {
    meta:
        original_name = "File010"
        file_type = "ZIP"
        file_size = 4155280
        original_md5 = "df23a5f65a651a5368a1f4c68b4537fc"
        original_sha1 = "fa74b7d0e1cec72539108a3cd9fc2bac6a7210e3"
        id = "010"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3C F3 21 F4 57 02 00 00 9F 16 00 00 13 00 C0 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_011_ZIP_aa4fe812 {
    meta:
        original_name = "File011"
        file_type = "ZIP"
        file_size = 12996644
        original_md5 = "aa4fe812dc7a13e684d33bb70f3e4265"
        original_sha1 = "69c37b69b78a41efd19eea6d67b4b9b3eea1aa38"
        id = "011"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0F 02 00 00 0F 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_012_ZIP_cd7a8a6e {
    meta:
        original_name = "File012"
        file_type = "ZIP"
        file_size = 28659
        original_md5 = "cd7a8a6e473ca1693ae557da91650b8b"
        original_sha1 = "94158316e899691b587a346e5a5e5df2d6fcf437"
        id = "012"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 04 E8 63 06 F7 01 00 00 9B 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_013_CUSTOM_UNKNOWN_BIN_2d9a7072 {
    meta:
        original_name = "File013"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 814
        original_md5 = "2d9a7072177dd37a9fbacbdaf12b8b35"
        original_sha1 = "53b44947beaece17dc8d6c48ad2c8e5799a5ecb7"
        id = "013"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 4D 44 35 20 63 68 65 63 6B 73 75 6D 20 6F 66 20 61 20 66 69 6C 65 }

    condition:
        $magic_bytes at 0
}


rule rule_014_ZIP_79c0374c {
    meta:
        original_name = "File014"
        file_type = "ZIP"
        file_size = 3050393
        original_md5 = "79c0374c3dc8abfddac0c302d0330529"
        original_sha1 = "9ba252ab7303b9dbd6df8aab350e88da7f43fc1d"
        id = "014"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E4 A7 B0 6F EB 01 00 00 35 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_015_CUSTOM_UNKNOWN_BIN_e4507f2e {
    meta:
        original_name = "File015"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 164
        original_md5 = "e4507f2ec05eb69d935540e5b4d7ec5e"
        original_sha1 = "6079a4fc71df42383ada4142dffd97be27c483ea"
        id = "015"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 75 6E 74 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 30 20 2B 20 31 0D 0A 65 63 68 6F 20 47 }

    condition:
        $magic_bytes at 0
}


rule rule_016_CUSTOM_UNKNOWN_BIN_e71bb959 {
    meta:
        original_name = "File016"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 87
        original_md5 = "e71bb959c29c164e77ae88bca85852d2"
        original_sha1 = "f29968c8621ec698f98f555172a0b0a2fadbcb53"
        id = "016"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 68 65 78 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 35 35 0D 0A 73 65 74 20 2F 61 20 68 65 78 32 }

    condition:
        $magic_bytes at 0
}


rule rule_017_ZIP_c374b2ca {
    meta:
        original_name = "File017"
        file_type = "ZIP"
        file_size = 4810789
        original_md5 = "c374b2cac48b3b80144865fa7f181c2e"
        original_sha1 = "421b51dc3fd04041d3bac7434174e80f708b056d"
        id = "017"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0D 02 00 00 0D 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_018_PDF_5bd7a1b4 {
    meta:
        original_name = "File018"
        file_type = "PDF"
        file_size = 407134
        original_md5 = "5bd7a1b4904acc6280e2c1924a627860"
        original_sha1 = "2881a4e443a0aab7839bdf5647e9438afbe8bf24"
        id = "018"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 35 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 50 61 67 65 73 20 32 20 }

    condition:
        $magic_bytes at 0
}


rule rule_019_PNG_9d508931 {
    meta:
        original_name = "File019"
        file_type = "PNG"
        file_size = 1651234
        original_md5 = "9d5089314e21bb5001c52cb6228d9e0a"
        original_sha1 = "ac7b220cbe0494f89ce685d7cbed849f2f992b73"
        id = "019"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 79 B0 25 D7 79 }

    condition:
        $magic_bytes at 0
}


rule rule_020_CUSTOM_NULLPAD_2452330b {
    meta:
        original_name = "File020"
        file_type = "CUSTOM_NULLPAD"
        file_size = 38102
        original_md5 = "2452330b9f8f2c566f6b7c54d53c711a"
        original_sha1 = "2fb25f4805f11d6f21f0d0b06f247ebab6799d59"
        id = "020"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6F 00 6E 00 20 00 34 00 2E 00 30 00 20 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 74 00 69 00 }

    condition:
        $magic_bytes at 0
}


rule rule_021_CUSTOM_UNKNOWN_BIN_81936e46 {
    meta:
        original_name = "File021"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 35182
        original_md5 = "81936e46314e4a094681aa5a17eb0ed8"
        original_sha1 = "231b5648b1bc13c805553b5d644650f9d17422bd"
        id = "021"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 41 46 46 45 52 4F 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 }

    condition:
        $magic_bytes at 0
}


rule rule_022_PDF_dc76bac3 {
    meta:
        original_name = "File022"
        file_type = "PDF"
        file_size = 185443
        original_md5 = "dc76bac39b0b05024c5dc4e167430170"
        original_sha1 = "994bddfd345637ae2abcdd587fe884ccee627104"
        id = "022"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 50 61 67 65 73 20 32 20 30 20 52 0A 2F 54 79 70 65 20 2F 43 61 74 61 }

    condition:
        $magic_bytes at 0
}


rule rule_023_CUSTOM_NULLPAD_9c301375 {
    meta:
        original_name = "File023"
        file_type = "CUSTOM_NULLPAD"
        file_size = 686849
        original_md5 = "9c301375efa5c4613b55b7ae9178d837"
        original_sha1 = "3c43b63251acb488c47854a2752328525fcb7259"
        id = "023"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 49 44 33 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_024_EXE_371de9cf {
    meta:
        original_name = "File024"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "371de9cf8b4b2520ab224038f0e6b9a5"
        original_sha1 = "6d2054702bdae5168522981080051e39da3291e1"
        id = "024"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_025_EXE_0aca6a84 {
    meta:
        original_name = "File025"
        file_type = "EXE"
        file_size = 23832
        original_md5 = "0aca6a84b2b047abb36e3fb35b7938d3"
        original_sha1 = "d2dd2739ac3d2f496a7a5c849bcd2e12142d09ec"
        id = "025"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_026_CUSTOM_UNKNOWN_BIN_4e5ec44f {
    meta:
        original_name = "File026"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 35821
        original_md5 = "4e5ec44fe5564450f9c1061ad18aeb38"
        original_sha1 = "dc447a64136642636d7aa32e50c76e2465801c5f"
        id = "026"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 4E 53 45 0D 0A 20 20 }

    condition:
        $magic_bytes at 0
}


rule rule_027_EXE_899c8ae4 {
    meta:
        original_name = "File027"
        file_type = "EXE"
        file_size = 3584
        original_md5 = "899c8ae4b45a7d4957468e47833bc84d"
        original_sha1 = "13513de250639b432094dacbd14668339ca6b2a3"
        id = "027"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_028_CUSTOM_UNKNOWN_BIN_3d809cda {
    meta:
        original_name = "File028"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 109
        original_md5 = "3d809cda8a3b43c52a692d24e21af70b"
        original_sha1 = "0b4c9a6830f3d0b511fbb5af8cc492bde2715f4d"
        id = "028"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 64 69 65 31 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 36 20 2B 20 31 0D 0A 73 65 74 20 2F 61 20 64 }

    condition:
        $magic_bytes at 0
}


rule rule_029_CUSTOM_UNKNOWN_BIN_67571555 {
    meta:
        original_name = "File029"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 273
        original_md5 = "67571555f67b3a0b1cfb5b7efb8fa446"
        original_sha1 = "62c8a155d9a89b9442a85588bac0138b226500f2"
        id = "029"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 66 6F 72 20 2F 66 20 22 74 6F 6B 65 6E 73 3D 31 2D 34 20 64 65 6C 69 6D 73 3D 2F 20 22 20 25 25 61 20 69 6E 20 28 22 }

    condition:
        $magic_bytes at 0
}


rule rule_030_ZIP_da3fc8e4 {
    meta:
        original_name = "File030"
        file_type = "ZIP"
        file_size = 5379567
        original_md5 = "da3fc8e4d769d1655552f9c000312c67"
        original_sha1 = "d4e97f94ed56361255d38a8559758e98b36324fb"
        id = "030"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 64 02 00 00 64 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_031_ZIP_18ae60e9 {
    meta:
        original_name = "File031"
        file_type = "ZIP"
        file_size = 59159
        original_md5 = "18ae60e913174c448c66c4bb674936e7"
        original_sha1 = "10d5a709306eb512560ddbe30e601a9e9008cf9e"
        id = "031"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 98 84 F0 A8 EB 01 00 00 22 0A 00 00 13 00 CA 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_032_ZIP_93048e6c {
    meta:
        original_name = "File032"
        file_type = "ZIP"
        file_size = 176259
        original_md5 = "93048e6c41c1e52a2be85096b8df6614"
        original_sha1 = "5db12a5ec83b30e7b4d690f60159afd7e027fe04"
        id = "032"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E6 79 A3 97 BA 01 00 00 7D 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_033_CUSTOM_UNKNOWN_BIN_8f037af8 {
    meta:
        original_name = "File033"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 31332
        original_md5 = "8f037af809f60b33d6325be04e7e2747"
        original_sha1 = "a94507bb7a4c6b0ee11b752d8b385d215ce34473"
        id = "033"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 AA F7 58 A4 79 01 00 00 14 06 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_034_CUSTOM_UNKNOWN_BIN_98c35c46 {
    meta:
        original_name = "File034"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 77
        original_md5 = "98c35c46893f75f22975e6c1ab6131e0"
        original_sha1 = "f255dac4e27bb6793a05f093452b3c411a076f07"
        id = "034"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6E 75 6D 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 30 30 30 30 0D 0A 65 63 68 6F 20 59 6F 75 72 }

    condition:
        $magic_bytes at 0
}


rule rule_035_ZIP_0c5393a7 {
    meta:
        original_name = "File035"
        file_type = "ZIP"
        file_size = 3097388
        original_md5 = "0c5393a75584590513c78674fa3f0d6f"
        original_sha1 = "09671885a19250f7c5512043ea3816b174e150e5"
        id = "035"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 00 00 08 00 00 00 21 00 61 0D D4 92 42 02 00 00 75 14 00 00 13 00 00 00 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C CC }

    condition:
        $magic_bytes at 0
}


rule rule_036_PNG_a272e6b7 {
    meta:
        original_name = "File036"
        file_type = "PNG"
        file_size = 1417519
        original_md5 = "a272e6b746211b62152db107c265ec14"
        original_sha1 = "9720f66f73dcbe0ab836b55ed8e8ca6ff343744a"
        id = "036"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 B0 65 59 76 }

    condition:
        $magic_bytes at 0
}


rule rule_037_ZIP_10c891b8 {
    meta:
        original_name = "File037"
        file_type = "ZIP"
        file_size = 266343
        original_md5 = "10c891b8ebc12cc4066af9a675d637e0"
        original_sha1 = "295cbc82d0451974ed79e2f19c79be35861d6fb0"
        id = "037"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 35 02 00 00 35 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_038_CUSTOM_UNKNOWN_BIN_ee65f859 {
    meta:
        original_name = "File038"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 5125758
        original_md5 = "ee65f859755a2a7aae846761cccad234"
        original_sha1 = "9cac09cf3f08cdfa6042d1bc8ef45cdbb1ad7f8e"
        id = "038"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 43 44 30 30 31 2E 36 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 4D 65 74 61 64 61 74 61 20 32 20 30 20 52 0A 2F 4C 61 6E 67 20 28 65 6E }

    condition:
        $magic_bytes at 0
}


rule rule_039_CUSTOM_UNKNOWN_BIN_8f179f9b {
    meta:
        original_name = "File039"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 608
        original_md5 = "8f179f9b48d6c13fa96e801c31c5120b"
        original_sha1 = "97a36bda7a3707c371a61ca1be5babd819f22dfc"
        id = "039"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 44 69 73 63 6F 72 64 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }

    condition:
        $magic_bytes at 0
}


rule rule_040_CUSTOM_UNKNOWN_BIN_9ed8f42c {
    meta:
        original_name = "File040"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 168
        original_md5 = "9ed8f42ccba544d90543e5f82e255fac"
        original_sha1 = "b8c466614bb3ec0e42d6c56c601dda2b44fc7107"
        id = "040"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 69 6E 70 75 74 3D 68 65 6C 6C 6F 0D 0A 73 65 74 20 72 65 76 65 72 73 65 64 3D 0D 0A 66 6F 72 20 2F 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_041_PNG_6f821e51 {
    meta:
        original_name = "File041"
        file_type = "PNG"
        file_size = 1640375
        original_md5 = "6f821e51b6c6f33e1768187ddd1fba46"
        original_sha1 = "9d978cfbbe2db83aa8c852ec6955ddbf1969e504"
        id = "041"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 92 24 4B 92 }

    condition:
        $magic_bytes at 0
}


rule rule_042_EXE_74a4b714 {
    meta:
        original_name = "File042"
        file_type = "EXE"
        file_size = 11280
        original_md5 = "74a4b714c851de93c773b1772a40807d"
        original_sha1 = "48506056f569a40ee28155c507e3578af5ea4579"
        id = "042"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_043_ZIP_43e1b1fb {
    meta:
        original_name = "File043"
        file_type = "ZIP"
        file_size = 106799
        original_md5 = "43e1b1fb5bcd16c937b0da2c4a6e540c"
        original_sha1 = "661d2ddf9bd727de31c653aba3edd83c19e0959a"
        id = "043"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 02 00 08 00 4A 24 76 59 FB 70 55 3B 11 53 00 00 49 4E 03 00 11 00 11 00 77 6F 72 64 2F 64 6F 63 75 6D 65 6E 74 2E 78 6D 6C 55 54 0D }

    condition:
        $magic_bytes at 0
}


rule rule_044_CUSTOM_UNKNOWN_BIN_58e6cf4d {
    meta:
        original_name = "File044"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 229
        original_md5 = "58e6cf4d000a0330e09c022cf94f9be7"
        original_sha1 = "8318fd3c54c48db49737abadab240afb2c7fa7e3"
        id = "044"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 6C 6F 63 61 6C 20 65 6E 61 62 6C 65 64 65 6C 61 79 65 64 65 78 70 61 6E 73 69 6F 6E 0D 0A 73 65 74 20 77 6F }

    condition:
        $magic_bytes at 0
}


rule rule_045_JPEG_EXIF_6d8f6f9f {
    meta:
        original_name = "File045"
        file_type = "JPEG_EXIF"
        file_size = 137878
        original_md5 = "6d8f6f9f0df51f804f0d9e706373d881"
        original_sha1 = "1a4ac39badd635bb1a9e764a70e72fa901b3c98d"
        id = "045"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E1 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_046_EXE_f63d16a4 {
    meta:
        original_name = "File046"
        file_type = "EXE"
        file_size = 80947
        original_md5 = "f63d16a402673307cbd7e0a69205baa4"
        original_sha1 = "afb6c414197688a1bc6c113bb5add0f02f308a50"
        id = "046"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_047_EXE_130368dc {
    meta:
        original_name = "File047"
        file_type = "EXE"
        file_size = 1082258
        original_md5 = "130368dcac9cf8171b792bb164b1cd1c"
        original_sha1 = "a4609bedc4d885a3c0dd0f3fc9757af6a377dc8c"
        id = "047"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_048_CUSTOM_UNKNOWN_BIN_e117cf34 {
    meta:
        original_name = "File048"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 831
        original_md5 = "e117cf3498fa380b6c06de68232ee65a"
        original_sha1 = "f6745cee730e1665db5932e0ab51d53a885a5ea8"
        id = "048"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 31 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A 2E 44 }

    condition:
        $magic_bytes at 0
}


rule rule_049_CUSTOM_UNKNOWN_BIN_42823282 {
    meta:
        original_name = "File049"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1804
        original_md5 = "428232826229b4484bd2a9de0091b60e"
        original_sha1 = "1819ba9f99f764843716e04ed1d150fbe9efa16d"
        id = "049"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 62 61 73 69 63 20 61 70 70 73 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A }

    condition:
        $magic_bytes at 0
}


rule rule_050_CUSTOM_UNKNOWN_BIN_c9ee034b {
    meta:
        original_name = "File050"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 86
        original_md5 = "c9ee034bbc5f70cc0246bde27c1be76f"
        original_sha1 = "600cc227ee8d10820ed06a214b58ea151c213371"
        id = "050"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 6C 6F 72 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 36 0D 0A 63 6F 6C 6F 72 20 25 63 6F 6C }

    condition:
        $magic_bytes at 0
}


rule rule_051_EXE_db97870e {
    meta:
        original_name = "File051"
        file_type = "EXE"
        file_size = 716249
        original_md5 = "db97870e110d2e495f191c432797ad04"
        original_sha1 = "3a73e650e6386cfd23f3d726c347a9359a37478b"
        id = "051"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_052_JPEG_JFIF_a978b63e {
    meta:
        original_name = "File052"
        file_type = "JPEG_JFIF"
        file_size = 146273
        original_md5 = "a978b63e14d67b4d8a9625655adb3838"
        original_sha1 = "2aebfa2cce4c9a5498dc9541bee9cb27cce887ab"
        id = "052"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_053_JPEG_JFIF_b7bbbb11 {
    meta:
        original_name = "File053"
        file_type = "JPEG_JFIF"
        file_size = 173909
        original_md5 = "b7bbbb113e2913b4d54d17b47ec11308"
        original_sha1 = "e7840553b64fad9bab39e0c5a138e21a18d313ee"
        id = "053"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_054_CUSTOM_UNKNOWN_BIN_2c644420 {
    meta:
        original_name = "File054"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 628
        original_md5 = "2c6444207e051dbb8f9f8ceb8f05bd06"
        original_sha1 = "7df60f39ece494a400b4afb33484d4652cd16003"
        id = "054"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 47 69 74 20 66 6F 72 20 57 69 6E 64 6F 77 73 0A 2E 44 45 53 43 52 49 50 }

    condition:
        $magic_bytes at 0
}


rule rule_055_CUSTOM_UNKNOWN_BIN_38681205 {
    meta:
        original_name = "File055"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 844097
        original_md5 = "386812055de7c60fd297046a661ffd76"
        original_sha1 = "7e5659b43870dffc2bc7e1cebaf5aab028085d4f"
        id = "055"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 A9 90 C0 AD 7B 03 00 00 D3 10 00 00 14 00 00 00 70 70 74 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C }

    condition:
        $magic_bytes at 0
}


rule rule_056_ZIP_1c03344f {
    meta:
        original_name = "File056"
        file_type = "ZIP"
        file_size = 340390
        original_md5 = "1c03344f83275ac70b5391df2e8e0876"
        original_sha1 = "bcc8198a1d3d16525e4bf56a0d42a078a8893424"
        id = "056"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF F3 01 00 00 F3 01 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_057_CUSTOM_UNKNOWN_BIN_7e40596c {
    meta:
        original_name = "File057"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 691
        original_md5 = "7e40596c2d0399b64cc871ff4158ae57"
        original_sha1 = "f440d75b7b3c54939699edb42c48fed43ed131b1"
        id = "057"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 45 6E 61 62 6C 65 73 20 74 68 65 20 67 6F 64 20 6D 6F 64 65 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E }

    condition:
        $magic_bytes at 0
}


rule rule_058_CUSTOM_NULLPAD_18039dad {
    meta:
        original_name = "File058"
        file_type = "CUSTOM_NULLPAD"
        file_size = 23112
        original_md5 = "18039dade136470d4112c839cc043efe"
        original_sha1 = "6cd50628e742766f69ce4dd62c8a351b4eefc8c5"
        id = "058"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }

    condition:
        $magic_bytes at 0
}


rule rule_059_PNG_ebc5f898 {
    meta:
        original_name = "File059"
        file_type = "PNG"
        file_size = 1720207
        original_md5 = "ebc5f89869f7306fe420ca02a9677f9f"
        original_sha1 = "d8096c532ab21c705c08de6304672f2a0e6def72"
        id = "059"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B3 6D 49 76 }

    condition:
        $magic_bytes at 0
}


rule rule_060_EXE_8d404ac6 {
    meta:
        original_name = "File060"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "8d404ac68cc517b456d0c46305caf6b4"
        original_sha1 = "da8c7f8945337943f5e1fe1d1513395144711333"
        id = "060"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_061_CUSTOM_UNKNOWN_BIN_0a9bbaa0 {
    meta:
        original_name = "File061"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 106
        original_md5 = "0a9bbaa0e74a6e389c73c1a18d9897ac"
        original_sha1 = "c4b960d9a12c103dcf41b68eedc34c1fb59e1c37"
        id = "061"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 64 65 6C 61 79 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 35 20 2B 20 31 0D 0A 74 69 6D 65 6F 75 74 }

    condition:
        $magic_bytes at 0
}


rule rule_062_EXE_f0c3b5b1 {
    meta:
        original_name = "File062"
        file_type = "EXE"
        file_size = 11272
        original_md5 = "f0c3b5b14d0b5c1420d1e22f3585f4c3"
        original_sha1 = "cde069a5cbc8bdefcff8a67dcf26538cf35eb99b"
        id = "062"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_063_CUSTOM_UNKNOWN_BIN_2b2cf30e {
    meta:
        original_name = "File063"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1962050
        original_md5 = "2b2cf30e60c4c5c6a7bfaf7f05f559b3"
        original_sha1 = "82cf0d9d4f3ea20c6e2f8f55c883865d5f77b5ae"
        id = "063"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 49 44 33 31 2E 34 0D 25 80 84 88 8C 90 94 98 9C A0 A4 A8 AC B0 B4 B8 BC C0 C4 C8 CC D0 D4 D8 DC E0 E4 E8 EC F0 F4 F8 FC 0D 0D 31 20 30 20 6F 62 6A 0D }

    condition:
        $magic_bytes at 0
}


rule rule_064_CUSTOM_UNKNOWN_BIN_ca807e6c {
    meta:
        original_name = "File064"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 2138
        original_md5 = "ca807e6ce43369833704d96678d19667"
        original_sha1 = "f53f88263eb2968f54c43bf34a4905d1c30ee469"
        id = "064"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 5B 4C 6F 63 61 6C 69 7A 65 64 46 69 6C 65 4E 61 6D 65 73 5D 0D 0A 62 69 6F 63 68 65 6D 5F 6D 65 64 2D 32 33 2D 32 2D 31 34 33 2D 33 2E 70 64 66 3D 40 }

    condition:
        $magic_bytes at 0
}


rule rule_065_CUSTOM_UNKNOWN_BIN_3ba7c710 {
    meta:
        original_name = "File065"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 756
        original_md5 = "3ba7c71043ab870a87d59a781def60a5"
        original_sha1 = "baeb7379a48da8345479b809c9084eb419d38764"
        id = "065"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 49 53 43 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A }

    condition:
        $magic_bytes at 0
}


rule rule_066_PDF_597122e0 {
    meta:
        original_name = "File066"
        file_type = "PDF"
        file_size = 3259060
        original_md5 = "597122e0437a3753b00487694f30de80"
        original_sha1 = "a99f8441c9dc40ce170c0b7e129caff0ee4206ea"
        id = "066"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 36 20 30 20 6F 62 6A 0A 3C 3C 2F 46 69 6C 74 65 72 2F 46 6C 61 74 65 44 65 63 6F 64 65 2F 4C 65 6E 67 74 }

    condition:
        $magic_bytes at 0
}


rule rule_067_EXE_ea15bc11 {
    meta:
        original_name = "File067"
        file_type = "EXE"
        file_size = 366608
        original_md5 = "ea15bc1156bf638002b99c63bd4abb1a"
        original_sha1 = "1256d16942369961683c7f21c7f77128ea1f73c9"
        id = "067"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 93 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_068_PNG_4f81b658 {
    meta:
        original_name = "File068"
        file_type = "PNG"
        file_size = 1485481
        original_md5 = "4f81b658e6cc40fbf7c4664e14b24a29"
        original_sha1 = "6dc6d6c0568f695a24a42fcedfcb2409aa550654"
        id = "068"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 AF 24 4B 92 }

    condition:
        $magic_bytes at 0
}


rule rule_069_PNG_314de58b {
    meta:
        original_name = "File069"
        file_type = "PNG"
        file_size = 170993
        original_md5 = "314de58ba4408e243fc5e7f691014c26"
        original_sha1 = "96deb65cd007cbcf829b7ff81e5629b03cd87907"
        id = "069"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B }

    condition:
        $magic_bytes at 0
}


rule rule_070_PNG_4effb217 {
    meta:
        original_name = "File070"
        file_type = "PNG"
        file_size = 1645439
        original_md5 = "4effb217ca55d93bb55192693ef0ee9c"
        original_sha1 = "72acaa872934217c3fc370c361a21e22853c6565"
        id = "070"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 49 B3 65 4B 76 }

    condition:
        $magic_bytes at 0
}


rule rule_071_EXE_08422e54 {
    meta:
        original_name = "File071"
        file_type = "EXE"
        file_size = 11792
        original_md5 = "08422e540f71afbf8895440dbce80aa4"
        original_sha1 = "22f690f251032776e47565d46f3285c4011695bd"
        id = "071"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_072_PNG_5956a153 {
    meta:
        original_name = "File072"
        file_type = "PNG"
        file_size = 1655833
        original_md5 = "5956a153b3144e3256047ab8eead83e5"
        original_sha1 = "463c9c107e470c360e75f5e7e569bd6c3a4ae9e1"
        id = "072"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 97 25 C9 71 }

    condition:
        $magic_bytes at 0
}


rule rule_073_JPEG_JFIF_614cf260 {
    meta:
        original_name = "File073"
        file_type = "JPEG_JFIF"
        file_size = 157801
        original_md5 = "614cf260d4d13d5ffb6f947cc806d671"
        original_sha1 = "8082d965f637e78065d417dcf7c42915e7cbb988"
        id = "073"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_074_ZIP_f9b2c6c6 {
    meta:
        original_name = "File074"
        file_type = "ZIP"
        file_size = 7213107
        original_md5 = "f9b2c6c68a3ddfc2678fcd9f0cf0464e"
        original_sha1 = "7178220d10182f9ab2c3efd1054a8872e24800e9"
        id = "074"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 2D 02 00 00 2D 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_075_EXE_cbf27b79 {
    meta:
        original_name = "File075"
        file_type = "EXE"
        file_size = 341331
        original_md5 = "cbf27b79169a22e2ed9f2f6ded176cdb"
        original_sha1 = "8929c844ae8a6f80694d0e8de149adbae60fd78a"
        id = "075"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_076_ZIP_585ce446 {
    meta:
        original_name = "File076"
        file_type = "ZIP"
        file_size = 115731
        original_md5 = "585ce4469a6adfebb17e5c7b1163f349"
        original_sha1 = "f90e097bb2880d250c2d1fe6d6d69f49a4c89ed3"
        id = "076"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 AB 0B 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 68 65 61 64 65 72 31 2E 78 6D 6C CD 96 DB 8E }

    condition:
        $magic_bytes at 0
}


rule rule_077_CUSTOM_UNKNOWN_BIN_f5fa09da {
    meta:
        original_name = "File077"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 603
        original_md5 = "f5fa09dace753bebba5b6075f127dc26"
        original_sha1 = "6b628dfe25adc892b188fbf79dd627b55f0474cd"
        id = "077"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 43 68 72 6F 6D 65 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 }

    condition:
        $magic_bytes at 0
}


rule rule_078_JPEG_JFIF_2431f8e7 {
    meta:
        original_name = "File078"
        file_type = "JPEG_JFIF"
        file_size = 160610
        original_md5 = "2431f8e75577a0e57896d66782cb9890"
        original_sha1 = "11df096f561dcf067384125730ea9c354217abef"
        id = "078"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_079_CUSTOM_NULLPAD_b6167a06 {
    meta:
        original_name = "File079"
        file_type = "CUSTOM_NULLPAD"
        file_size = 339655
        original_md5 = "b6167a060ce70bcc90de22e27a3fbb07"
        original_sha1 = "875417a1f75bd6b215b49df4ac0daf19697f412a"
        id = "079"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF FB 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_080_EXE_12961a8d {
    meta:
        original_name = "File080"
        file_type = "EXE"
        file_size = 11792
        original_md5 = "12961a8d12e77fc9b66345b80456f7fe"
        original_sha1 = "ec320d7a73dcf97b4b4fcb6e764a238a318e38c4"
        id = "080"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_081_EXE_52376b5f {
    meta:
        original_name = "File081"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "52376b5fbaa7a368612ca909730cf9b3"
        original_sha1 = "b4e26ea63c2994e7d994c052c52d3f4e8da27c9d"
        id = "081"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_082_CUSTOM_UNKNOWN_BIN_559dd7a8 {
    meta:
        original_name = "File082"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 147
        original_md5 = "559dd7a83d0d7688e334978e75d45beb"
        original_sha1 = "9fa22c8cb4ee7c89f6787dc7c131758bf524e13f"
        id = "082"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 70 61 74 68 73 3D 43 3A 5C 57 69 6E 64 6F 77 73 5C 20 43 3A 5C 55 73 65 72 73 5C 20 43 3A 5C 50 72 6F 67 }

    condition:
        $magic_bytes at 0
}


rule rule_083_CUSTOM_UNKNOWN_BIN_d324ff06 {
    meta:
        original_name = "File083"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 124
        original_md5 = "d324ff068ad2ee0ce710cfe951697116"
        original_sha1 = "5355854158f0f85378e0e61a6176f12e805af563"
        id = "083"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6E 75 6D 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 36 20 2B 20 36 35 0D 0A 66 6F 72 20 2F 66 20 }

    condition:
        $magic_bytes at 0
}


rule rule_084_PDF_0003f23e {
    meta:
        original_name = "File084"
        file_type = "PDF"
        file_size = 417316
        original_md5 = "0003f23eb36cf0145bb82e108295b143"
        original_sha1 = "c514b8f17c465ef3d259d44ba6af4295b568f802"
        id = "084"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 33 33 0A 2F }

    condition:
        $magic_bytes at 0
}


rule rule_085_ZIP_5a237806 {
    meta:
        original_name = "File085"
        file_type = "ZIP"
        file_size = 406205
        original_md5 = "5a237806a6afec0a40fb433530387001"
        original_sha1 = "3163223d1fc12c29ad6a01051f00054c5995f8c4"
        id = "085"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 CF 3E 7B 02 01 00 00 BB 02 00 00 0B 00 ED 01 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 E9 01 28 A0 00 02 00 }

    condition:
        $magic_bytes at 0
}


rule rule_086_CUSTOM_UNKNOWN_BIN_6130cc3a {
    meta:
        original_name = "File086"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 677
        original_md5 = "6130cc3a7797bd20785db9a1e38246bc"
        original_sha1 = "c60b117808fc4e70da2fbc77f3a66da0ff9d655c"
        id = "086"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 42 53 44 20 5A 65 72 6F 20 43 6C 61 75 73 65 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 }

    condition:
        $magic_bytes at 0
}


rule rule_087_ZIP_b4ea3fa8 {
    meta:
        original_name = "File087"
        file_type = "ZIP"
        file_size = 288249
        original_md5 = "b4ea3fa8c44c0e05e86e4b0d8859cf0f"
        original_sha1 = "ad9ada5e4004b1892ff0800575ffb3ba1ca2af0e"
        id = "087"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 8F BF F1 36 23 04 00 00 C5 4E 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_088_CUSTOM_UNKNOWN_BIN_822123f7 {
    meta:
        original_name = "File088"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 100
        original_md5 = "822123f73ba273c1a622f5d5cf32633b"
        original_sha1 = "3e089d46050c8b97e53a7892ff27fce5577062e9"
        id = "088"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 66 6F 72 20 2F 6C 20 25 25 69 20 69 6E 20 28 31 2C 31 2C 33 32 29 20 64 6F 20 28 0D 0A 20 20 20 20 73 65 74 20 2F 61 }

    condition:
        $magic_bytes at 0
}


rule rule_089_JPEG_JFIF_905363c4 {
    meta:
        original_name = "File089"
        file_type = "JPEG_JFIF"
        file_size = 180248
        original_md5 = "905363c4abd5f39bc6f98ff3e25b0281"
        original_sha1 = "3eea1966f23ac6499d0cb9a013a1d14fa1919fca"
        id = "089"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_090_JPEG_JFIF_3e736f01 {
    meta:
        original_name = "File090"
        file_type = "JPEG_JFIF"
        file_size = 169745
        original_md5 = "3e736f0149faed08b112e43245750aa8"
        original_sha1 = "20c0b1492e950b392bf8088f673a5bb9072983cc"
        id = "090"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_091_CUSTOM_UNKNOWN_BIN_00cf085b {
    meta:
        original_name = "File091"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 494
        original_md5 = "00cf085bfe51c5de71ff776ac8257e34"
        original_sha1 = "5b487a6cd44e96db251408822b2f08c833f77152"
        id = "091"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 44 4F 20 57 48 41 54 20 54 48 45 20 46 55 43 4B 20 59 4F 55 20 57 41 4E 54 20 54 4F 20 50 55 42 4C 49 43 20 4C 49 }

    condition:
        $magic_bytes at 0
}


rule rule_092_EXE_cb22ec32 {
    meta:
        original_name = "File092"
        file_type = "EXE"
        file_size = 412847
        original_md5 = "cb22ec32b6b7d83582b7fda7d682ff89"
        original_sha1 = "47a126f450d91264f4a399c52d25efb622d2a169"
        id = "092"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_093_ZIP_8a0b5139 {
    meta:
        original_name = "File093"
        file_type = "ZIP"
        file_size = 3038333
        original_md5 = "8a0b5139a1e35f636b28893cb6436fb9"
        original_sha1 = "2cc913d580f766965d2a1c95cc60303f84f5dece"
        id = "093"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9D 7C 73 2A E3 01 00 00 B5 0C 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_094_ZIP_d46229b6 {
    meta:
        original_name = "File094"
        file_type = "ZIP"
        file_size = 62950
        original_md5 = "d46229b61ac5fa694f1e5547d7cf424e"
        original_sha1 = "6e3978345a445e7e659069466f1707e46f8c15b7"
        id = "094"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 81 71 7D 3C F8 01 00 00 BA 0C 00 00 13 00 CD 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_095_EXE_bb24a4f2 {
    meta:
        original_name = "File095"
        file_type = "EXE"
        file_size = 259805
        original_md5 = "bb24a4f283eeeb0a5b6a63256e197fad"
        original_sha1 = "e8039cd053f2974edaa188541159dfe12bea125f"
        id = "095"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_096_ZIP_6b8f2e87 {
    meta:
        original_name = "File096"
        file_type = "ZIP"
        file_size = 187180
        original_md5 = "6b8f2e87dfddec9238fb7252e63ad558"
        original_sha1 = "f426e87d01f2d3d46e2217e053ffaf2b8f518511"
        id = "096"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 D5 71 95 3E E1 01 00 00 7A 09 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_097_CUSTOM_UNKNOWN_BIN_d9b96769 {
    meta:
        original_name = "File097"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 132678
        original_md5 = "d9b96769f85876192c5efcfa556ab7f4"
        original_sha1 = "fe10fede7cc3507280bc6913686a0488224abf47"
        id = "097"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D9 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_098_PNG_e23a8288 {
    meta:
        original_name = "File098"
        file_type = "PNG"
        file_size = 1684054
        original_md5 = "e23a82888ff953e592c9935f447348e7"
        original_sha1 = "78146598cdd205e741b122cf067352b1d7ec9cb7"
        id = "098"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 AC 6D DB 75 }

    condition:
        $magic_bytes at 0
}


rule rule_099_CUSTOM_UNKNOWN_BIN_492b4606 {
    meta:
        original_name = "File099"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 352
        original_md5 = "492b46063a1fa97a738da1a411aad4d1"
        original_sha1 = "a85e740b01159f63bf255c5feaa89eeb7a917766"
        id = "099"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 0A 22 31 2E 20 49 6E 73 74 61 6C 6C 20 61 6E 64 20 63 6F 6E 66 69 67 75 72 65 20 74 68 65 20 6E 65 63 65 73 73 61 72 79 20 64 65 70 65 6E 64 65 6E 63 }

    condition:
        $magic_bytes at 0
}


rule rule_100_ZIP_95b6f67c {
    meta:
        original_name = "File100"
        file_type = "ZIP"
        file_size = 27963
        original_md5 = "95b6f67c991027de4266a1e0e7e8d527"
        original_sha1 = "9be1f1347b642ed0becdc2fea3e4f272860a91d5"
        id = "100"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 1E 27 60 70 88 01 00 00 AE 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_101_EXE_b022e52f {
    meta:
        original_name = "File101"
        file_type = "EXE"
        file_size = 12816
        original_md5 = "b022e52fae3ea7da7b43c8e80ca646a9"
        original_sha1 = "cc1fab36ee81c119aae9856ebea2e1735a309b30"
        id = "101"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_102_CUSTOM_UNKNOWN_BIN_63acfbba {
    meta:
        original_name = "File102"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 196042
        original_md5 = "63acfbba8e6e6dfba235018deaad7ab6"
        original_sha1 = "6bb6cc99155a64d8a0210ffeb2d455c4f67b32fa"
        id = "102"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 52 49 46 46 57 41 56 45 2D 31 2E 36 0D 25 E2 E3 CF D3 0D 0A 35 39 20 30 20 6F 62 6A 20 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 31 39 36 }

    condition:
        $magic_bytes at 0
}


rule rule_103_PDF_1f6d1bba {
    meta:
        original_name = "File103"
        file_type = "PDF"
        file_size = 7474390
        original_md5 = "1f6d1bba0572b67079ce8b19f66377f4"
        original_sha1 = "310d4f9892781915a9b1a06be70a145e13089b8a"
        id = "103"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 34 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 56 65 72 73 69 6F 6E 20 }

    condition:
        $magic_bytes at 0
}


rule rule_104_ZIP_315c12e3 {
    meta:
        original_name = "File104"
        file_type = "ZIP"
        file_size = 1286316
        original_md5 = "315c12e381824fa8187634f37e4d12da"
        original_sha1 = "ceb6330fa3b9c7221d97447fff5201796eedc3d0"
        id = "104"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 2B 54 51 0E D9 02 00 00 A6 24 00 00 13 00 BA 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_105_PNG_2e8f9dd9 {
    meta:
        original_name = "File105"
        file_type = "PNG"
        file_size = 1426547
        original_md5 = "2e8f9dd9eacb56032b79a06250e949a6"
        original_sha1 = "1f7d9c86df7456e49ea0bc11e8a6a86c4c07923c"
        id = "105"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD F9 93 24 5B 76 }

    condition:
        $magic_bytes at 0
}


rule rule_106_CUSTOM_NULLPAD_fe975f76 {
    meta:
        original_name = "File106"
        file_type = "CUSTOM_NULLPAD"
        file_size = 28944
        original_md5 = "fe975f7601a2126ba0431d2e84cb71d8"
        original_sha1 = "9b6443c7c129555a34070863f8112406befea355"
        id = "106"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 45 00 63 00 6C 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6C 00 69 00 63 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 20 00 2D 00 20 00 }

    condition:
        $magic_bytes at 0
}


rule rule_107_JPEG_JFIF_62b5f962 {
    meta:
        original_name = "File107"
        file_type = "JPEG_JFIF"
        file_size = 142129
        original_md5 = "62b5f962ab419a0e7d39693a47f6f8cf"
        original_sha1 = "85f3663b76b7a5cf7a6a7509c92bfbffc574a15f"
        id = "107"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_108_PNG_2083b784 {
    meta:
        original_name = "File108"
        file_type = "PNG"
        file_size = 1544836
        original_md5 = "2083b7845475c50f4d3d0ce43abddf47"
        original_sha1 = "90f76c4eefb5140ed52e3cb09aa9dafe54e90501"
        id = "108"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B2 2C 49 92 }

    condition:
        $magic_bytes at 0
}


rule rule_109_CUSTOM_UNKNOWN_BIN_a8db5b9f {
    meta:
        original_name = "File109"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 556987
        original_md5 = "a8db5b9ff83ebe7e87a3971576158977"
        original_sha1 = "3ece35df69d47b45cf2f3d6cf825def15af9f531"
        id = "109"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 52 49 46 46 57 41 56 45 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 }

    condition:
        $magic_bytes at 0
}


rule rule_110_CUSTOM_UNKNOWN_BIN_8b17d3c1 {
    meta:
        original_name = "File110"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 2828
        original_md5 = "8b17d3c1a890583d649554e66df1c9e6"
        original_sha1 = "8e542857954afc39520828bcdd48bf58cd3f08eb"
        id = "110"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 69 63 72 6F 73 6F 66 74 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 28 4D 73 2D 50 4C 29 0D 0A 0D 0A 54 68 69 73 20 6C 69 63 65 6E 73 65 20 67 }

    condition:
        $magic_bytes at 0
}


rule rule_111_ZIP_bbfd94f7 {
    meta:
        original_name = "File111"
        file_type = "ZIP"
        file_size = 146438
        original_md5 = "bbfd94f750618d4eb4fc8c3d6a9ff11d"
        original_sha1 = "d21850fb8f7ff21a8d48aaa9bb928043416924eb"
        id = "111"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 45 8C 02 3A BC 01 00 00 64 08 00 00 13 00 DC 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_112_CUSTOM_UNKNOWN_BIN_c75dbb43 {
    meta:
        original_name = "File112"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 41
        original_md5 = "c75dbb43150fd2ce4732c77ef9997def"
        original_sha1 = "82c0591ef8737c0e3a74a0b98e4ba4f9996f1189"
        id = "112"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 65 63 68 6F 20 52 61 6E 64 6F 6D 20 53 74 72 69 6E 67 3A 20 25 72 61 6E 64 6F 6D 25 0D 0A }

    condition:
        $magic_bytes at 0
}


rule rule_113_JPEG_JFIF_8019c963 {
    meta:
        original_name = "File113"
        file_type = "JPEG_JFIF"
        file_size = 160547
        original_md5 = "8019c9631f622de19c81a3e19df8b4ed"
        original_sha1 = "eb7d1a333bc894fb8c1a9afa2f70768246f9fa0c"
        id = "113"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_114_PDF_9b702a3a {
    meta:
        original_name = "File114"
        file_type = "PDF"
        file_size = 527117
        original_md5 = "9b702a3a329410a22d2877816ece84c5"
        original_sha1 = "83e2b181ad279115050e23bce261ddd082f1b650"
        id = "114"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 32 30 0A 2F }

    condition:
        $magic_bytes at 0
}


rule rule_115_EXE_9e25484b {
    meta:
        original_name = "File115"
        file_type = "EXE"
        file_size = 1063014
        original_md5 = "9e25484b1907186fa37395a4c3b79940"
        original_sha1 = "65e3ec37850f9d2d5ef82f264171611be5414d5c"
        id = "115"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_116_ZIP_b153dc51 {
    meta:
        original_name = "File116"
        file_type = "ZIP"
        file_size = 694240
        original_md5 = "b153dc51097eaf6bc297727b41d16fa9"
        original_sha1 = "73c3036755de9c36bd22f36f0238d56dfd094240"
        id = "116"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 74 76 54 0C D0 01 00 00 6C 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_117_ZIP_0d7783aa {
    meta:
        original_name = "File117"
        file_type = "ZIP"
        file_size = 64531
        original_md5 = "0d7783aa3a521e6d64aa1a829c5ea90a"
        original_sha1 = "6a6a963ea8245d4034c2ebcc01e98e1c6feb3440"
        id = "117"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9C BD 3C E3 CE 01 00 00 C4 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_118_EXE_e729b5cc {
    meta:
        original_name = "File118"
        file_type = "EXE"
        file_size = 1080656
        original_md5 = "e729b5cc0ca22d973378a595f0c02cf8"
        original_sha1 = "c278fc9f054943a8bc9fb22e322e588d30494a4b"
        id = "118"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_119_CUSTOM_UNKNOWN_BIN_fdea5ae8 {
    meta:
        original_name = "File119"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 555
        original_md5 = "fdea5ae8a8ede952bc58bdb26b47d57a"
        original_sha1 = "8960ef02e567df940ebd6bd1f46c06a3565fbcf9"
        id = "119"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 54 77 69 74 74 65 72 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }

    condition:
        $magic_bytes at 0
}


rule rule_120_CUSTOM_UNKNOWN_BIN_0f3ee7c9 {
    meta:
        original_name = "File120"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 572
        original_md5 = "0f3ee7c9eb9340ae44a93bfcd27523ba"
        original_sha1 = "6d9e489b5b0f096484935299db389aa2fc42332c"
        id = "120"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 54 68 75 6E 64 65 72 62 69 72 64 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E }

    condition:
        $magic_bytes at 0
}


rule rule_121_ZIP_78db5fb8 {
    meta:
        original_name = "File121"
        file_type = "ZIP"
        file_size = 345850
        original_md5 = "78db5fb8d3b5f11d349384c5c808d94c"
        original_sha1 = "65b6579a5c5dbe6d42f49031bb4c416a0d36f254"
        id = "121"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9F 04 C7 C5 38 02 00 00 54 10 00 00 13 00 C2 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_122_ZIP_423e0563 {
    meta:
        original_name = "File122"
        file_type = "ZIP"
        file_size = 572074
        original_md5 = "423e0563fe719395891fa51a000a41ad"
        original_sha1 = "83e586e9a4ccd04f8c77cf11bca3d1339e891340"
        id = "122"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 48 A5 75 59 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 77 6F 72 64 2F 6E 75 6D 62 65 72 69 6E 67 2E 78 6D 6C ED 9B }

    condition:
        $magic_bytes at 0
}


rule rule_123_PDF_bd0ea60d {
    meta:
        original_name = "File123"
        file_type = "PDF"
        file_size = 521414
        original_md5 = "bd0ea60d14eea5566361109dc08af4ae"
        original_sha1 = "e84d7eedce3c34193739ab5f41af545a56467971"
        id = "123"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 35 0D 0A 25 B5 B5 B5 B5 0D 0A 31 20 30 20 6F 62 6A 0D 0A 3C 3C 2F 54 79 70 65 2F 43 61 74 61 6C 6F 67 2F 50 61 67 65 73 20 32 20 }

    condition:
        $magic_bytes at 0
}


rule rule_124_JPEG_JFIF_d2183bc6 {
    meta:
        original_name = "File124"
        file_type = "JPEG_JFIF"
        file_size = 173180
        original_md5 = "d2183bc6bc61647833e480df21079df5"
        original_sha1 = "eeb2d7a4366130e5523204e5e85832c7a0b2d5be"
        id = "124"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_125_PNG_b4eb8e22 {
    meta:
        original_name = "File125"
        file_type = "PNG"
        file_size = 1591997
        original_md5 = "b4eb8e22a873e2bff9a2c056c20da979"
        original_sha1 = "e182a3a956d31cf17eae094508ecda51bdf0f9b3"
        id = "125"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 67 B4 65 C9 75 }

    condition:
        $magic_bytes at 0
}


rule rule_126_PNG_eff3a759 {
    meta:
        original_name = "File126"
        file_type = "PNG"
        file_size = 1502871
        original_md5 = "eff3a759ab08c2c95fdba8c3cde7c1f8"
        original_sha1 = "2515298c9ac3310c0edada1f005041b1dacc8750"
        id = "126"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 77 B0 25 C9 79 }

    condition:
        $magic_bytes at 0
}


rule rule_127_JPEG_JFIF_07167ed9 {
    meta:
        original_name = "File127"
        file_type = "JPEG_JFIF"
        file_size = 154510
        original_md5 = "07167ed9288a6fb574bbb0ad229bf1b0"
        original_sha1 = "ce30a350e536ad0ae9af5f625a0213d6fbdd8e6b"
        id = "127"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_128_CUSTOM_UNKNOWN_BIN_c79e9121 {
    meta:
        original_name = "File128"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 87
        original_md5 = "c79e9121e51d9373a410b53ae8a3d964"
        original_sha1 = "52bf71c606ab98d918cda1fae17ecbdaf58fe34d"
        id = "128"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 64 65 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 35 35 0D 0A 65 63 68 6F 20 45 78 69 74 69 }

    condition:
        $magic_bytes at 0
}


rule rule_129_PDF_321ae2c8 {
    meta:
        original_name = "File129"
        file_type = "PDF"
        file_size = 217395
        original_md5 = "321ae2c8ccc6a16073c16910ec598891"
        original_sha1 = "c0ec1fdf59c40d422a2fc1d63bc7fb23c845db7a"
        id = "129"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 31 39 0A 2F }

    condition:
        $magic_bytes at 0
}


rule rule_130_ZIP_1e40fe72 {
    meta:
        original_name = "File130"
        file_type = "ZIP"
        file_size = 100153
        original_md5 = "1e40fe728f54ab560be84048b37e2136"
        original_sha1 = "5be30928b8af0b3e684761d3e192bc7d52692a0e"
        id = "130"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3D 57 87 34 C6 01 00 00 BF 08 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_131_ZIP_ec026d8e {
    meta:
        original_name = "File131"
        file_type = "ZIP"
        file_size = 26769
        original_md5 = "ec026d8ed4a1aeaeca8eeb4e7bd17715"
        original_sha1 = "25d67d32197d0c32dab7c19404d7d33eb6c3e89b"
        id = "131"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 A6 74 04 52 85 01 00 00 AC 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_132_PDF_d0787c3c {
    meta:
        original_name = "File132"
        file_type = "PDF"
        file_size = 588152
        original_md5 = "d0787c3ca7aab644472e1a015c23597c"
        original_sha1 = "7c0efa4720977994df80da127d1f3fd7f278d197"
        id = "132"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 36 0D 25 E2 E3 CF D3 0D 0A 34 33 31 20 30 20 6F 62 6A 0D 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 35 38 38 31 35 32 }

    condition:
        $magic_bytes at 0
}


rule rule_133_JPEG_JFIF_89e432c5 {
    meta:
        original_name = "File133"
        file_type = "JPEG_JFIF"
        file_size = 159149
        original_md5 = "89e432c568ecd36d5136ce58c923eb9a"
        original_sha1 = "0d7e846937431043925526e882e17ca758adb83d"
        id = "133"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_134_ZIP_d6eadec7 {
    meta:
        original_name = "File134"
        file_type = "ZIP"
        file_size = 744699
        original_md5 = "d6eadec77ea7a7436fb9e5f39bdc9b36"
        original_sha1 = "711fdd86b47733ffdeeec89f21a52c540ee7c23a"
        id = "134"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3D 57 87 34 C6 01 00 00 BF 08 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_135_PDF_14ca718f {
    meta:
        original_name = "File135"
        file_type = "PDF"
        file_size = 5765224
        original_md5 = "14ca718fd2c6718e4a31472da950627a"
        original_sha1 = "363e3fb566ee15d4f4a5c35ceefbd5d1a5343f03"
        id = "135"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0D 25 E2 E3 CF D3 0D 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 41 63 72 6F 46 6F 72 6D 20 35 20 30 20 52 2F 4C 61 6E 67 28 65 6E 29 }

    condition:
        $magic_bytes at 0
}


rule rule_136_CUSTOM_UNKNOWN_BIN_31bbd832 {
    meta:
        original_name = "File136"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1809714
        original_md5 = "31bbd83292460bdfb30a7bd9ff9aaf4b"
        original_sha1 = "369cc313e0ff83e79e030eb69673e2287386f3d8"
        id = "136"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 5B B3 24 49 92 1E 88 7D AA 66 EE 1E 71 }

    condition:
        $magic_bytes at 0
}


rule rule_137_CUSTOM_UNKNOWN_BIN_81543b22 {
    meta:
        original_name = "File137"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1359
        original_md5 = "81543b22c36f10d20ac9712f8d80ef8d"
        original_sha1 = "892b34f7865d90a6f949f50d95e49625a10bc7f0"
        id = "137"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 42 6F 6F 73 74 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 2D 20 56 65 72 73 69 6F 6E 20 31 2E 30 20 2D 20 41 75 67 75 73 74 20 31 37 74 68 }

    condition:
        $magic_bytes at 0
}


rule rule_138_PDF_302b502d {
    meta:
        original_name = "File138"
        file_type = "PDF"
        file_size = 663177
        original_md5 = "302b502d4e62ce9364d06014e544c095"
        original_sha1 = "418baca3e862279dd832d4489d6a82d8665168ba"
        id = "138"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 43 6F 6C 6F 72 53 70 61 63 65 2F 44 65 76 69 63 65 47 72 61 79 2F 53 75 }

    condition:
        $magic_bytes at 0
}


rule rule_139_CUSTOM_UNKNOWN_BIN_0618ec59 {
    meta:
        original_name = "File139"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 168
        original_md5 = "0618ec59c2401e95bc66f5f48bb46bdc"
        original_sha1 = "de10d7b09c2b49ae3b8beda9ee949f1cf084a519"
        id = "139"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 73 65 6E 74 65 6E 63 65 73 3D 48 65 6C 6C 6F 7C 48 6F 77 20 61 72 65 20 79 6F 75 3F 7C 4E 69 63 65 20 77 }

    condition:
        $magic_bytes at 0
}


rule rule_140_JPEG_JFIF_f83e3fd9 {
    meta:
        original_name = "File140"
        file_type = "JPEG_JFIF"
        file_size = 157962
        original_md5 = "f83e3fd9b34363578c2128dc3eac6f01"
        original_sha1 = "64d091ad38f3289dcdaac720635577f1fabbcea6"
        id = "140"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_141_EXE_ac1b9414 {
    meta:
        original_name = "File141"
        file_type = "EXE"
        file_size = 472874
        original_md5 = "ac1b94145d5bf11f34eba1137d8b39e2"
        original_sha1 = "c33584ab2f523cbb8556599ccbefc67129602668"
        id = "141"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_142_ZIP_ecf92b48 {
    meta:
        original_name = "File142"
        file_type = "ZIP"
        file_size = 2693126
        original_md5 = "ecf92b48eaa6ff7d658170aa49a6e660"
        original_sha1 = "ab486d834224d33b59515b7d1c738911b949c126"
        id = "142"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 08 00 00 00 21 00 03 E4 7B FE C7 03 00 00 91 13 00 00 14 00 00 00 70 70 74 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C }

    condition:
        $magic_bytes at 0
}


rule rule_143_CUSTOM_UNKNOWN_BIN_cef114c5 {
    meta:
        original_name = "File143"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1635658
        original_md5 = "cef114c5875ba465fbdcb7dc7b297a42"
        original_sha1 = "b0e30d82001184e7373b2576fc229609046f104f"
        id = "143"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 93 24 49 92 26 88 7D CC 22 }

    condition:
        $magic_bytes at 0
}


rule rule_144_ZIP_d19b9663 {
    meta:
        original_name = "File144"
        file_type = "ZIP"
        file_size = 2490902
        original_md5 = "d19b96636f75b86f0f2740e6434e7b6f"
        original_sha1 = "e601679953b0423457f636adb46fd7b3192cf6e1"
        id = "144"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 1C 02 00 00 1C 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_145_ZIP_d688f330 {
    meta:
        original_name = "File145"
        file_type = "ZIP"
        file_size = 82840
        original_md5 = "d688f330a67743da9edf360bd87a4757"
        original_sha1 = "50314186f6005a2f6383fbfb9f112588096a9323"
        id = "145"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 FF BF 18 7A 2E 02 00 00 57 0D 00 00 13 00 C2 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_146_EXE_290a44f9 {
    meta:
        original_name = "File146"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "290a44f94f15d6ae35915320294947f6"
        original_sha1 = "dbba2d945d3a10d313896d32d90af9278559bba6"
        id = "146"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_147_CUSTOM_UNKNOWN_BIN_a4da8072 {
    meta:
        original_name = "File147"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 156
        original_md5 = "a4da80722c9b88f6fd9261637af70098"
        original_sha1 = "15d07a19e6cdfeca5bec0472779a3a4258e759e2"
        id = "147"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 6D 65 73 73 61 67 65 3D 4C 6F 61 64 69 6E 67 20 72 61 6E 64 6F 6D 20 74 65 78 74 2E 2E 2E 0D 0A 66 6F 72 }

    condition:
        $magic_bytes at 0
}


rule rule_148_CUSTOM_NULLPAD_ef063d46 {
    meta:
        original_name = "File148"
        file_type = "CUSTOM_NULLPAD"
        file_size = 315392
        original_md5 = "ef063d467563865aa7a97b4dae9924ce"
        original_sha1 = "c87af5eee0cfaf88c5176d1ba7591bee24a32673"
        id = "148"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF FB 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_149_ZIP_0a35b950 {
    meta:
        original_name = "File149"
        file_type = "ZIP"
        file_size = 27228
        original_md5 = "0a35b9503060597bb052f21b4b4290d6"
        original_sha1 = "98629156401fa0e895aed31c838fd1519d2674ec"
        id = "149"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 CE 13 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 66 6F 6F 74 65 72 31 2E 78 6D 6C ED 57 FF 6E }

    condition:
        $magic_bytes at 0
}


rule rule_150_ZIP_4cc3cee0 {
    meta:
        original_name = "File150"
        file_type = "ZIP"
        file_size = 955283
        original_md5 = "4cc3cee04f7e695a8de8591e15f19fc1"
        original_sha1 = "06b1ffb9db80cdce1e1623453882ed96b9602335"
        id = "150"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 20 02 00 00 20 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_151_ZIP_c0e566ec {
    meta:
        original_name = "File151"
        file_type = "ZIP"
        file_size = 4723372
        original_md5 = "c0e566ec23e885ddeb11e5a4070fb841"
        original_sha1 = "4247d02a033cb899485941a63f2f36e76c76c65f"
        id = "151"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B7 BB C7 DC A4 02 00 00 00 25 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_152_JPEG_JFIF_d647f671 {
    meta:
        original_name = "File152"
        file_type = "JPEG_JFIF"
        file_size = 151135
        original_md5 = "d647f67138863d8bf85b246774392709"
        original_sha1 = "c5eec9ec4683f0eafa40897a37d7d88b52fc21a6"
        id = "152"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_153_ZIP_07b039a5 {
    meta:
        original_name = "File153"
        file_type = "ZIP"
        file_size = 40590
        original_md5 = "07b039a576b247f2719d7c1372e7d1c7"
        original_sha1 = "8ade27f7dcc94cc0537bfa99754daaf97b8adbff"
        id = "153"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 BA BB 75 55 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 78 6C 2F 63 6F 6D 6D 65 6E 74 73 31 2E 78 6D 6C 8D 53 CB 6E }

    condition:
        $magic_bytes at 0
}


rule rule_154_CUSTOM_NULLPAD_a1c1ccba {
    meta:
        original_name = "File154"
        file_type = "CUSTOM_NULLPAD"
        file_size = 22534
        original_md5 = "a1c1ccba318f1630f5ffbdca6cdd12b2"
        original_sha1 = "926b7d6b492c6f9c315cfbfbec82a7bbcad7d30b"
        id = "154"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6F 00 6E 00 61 00 6C 00 20 00 43 00 6F 00 6D 00 6D 00 75 00 6E 00 69 00 74 00 79 00 20 00 4C 00 69 00 63 00 }

    condition:
        $magic_bytes at 0
}


rule rule_155_EXE_774faa35 {
    meta:
        original_name = "File155"
        file_type = "EXE"
        file_size = 301568
        original_md5 = "774faa35314ccf72d1b9d841b4532b03"
        original_sha1 = "ef57d337b2480bf4981091d9ec3072494f3c76f1"
        id = "155"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_156_PDF_8e984f34 {
    meta:
        original_name = "File156"
        file_type = "PDF"
        file_size = 347444
        original_md5 = "8e984f349c1855d2ac331a822f548ddd"
        original_sha1 = "a8a0da335bc884d7c7314719036f326c92233995"
        id = "156"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 50 61 67 65 73 20 32 20 }

    condition:
        $magic_bytes at 0
}


rule rule_157_CUSTOM_UNKNOWN_BIN_362889c2 {
    meta:
        original_name = "File157"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 10483
        original_md5 = "362889c21e1a9f7404c13205ea1b9fde"
        original_sha1 = "5c86fc5e9473205eba78ad2f46718d01c588b502"
        id = "157"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 41 63 61 64 65 6D 69 63 20 46 72 65 65 20 4C 69 63 65 6E 73 65 20 28 22 41 46 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 41 63 61 64 65 }

    condition:
        $magic_bytes at 0
}


rule rule_158_CUSTOM_UNKNOWN_BIN_5eba08d4 {
    meta:
        original_name = "File158"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 631
        original_md5 = "5eba08d45abbd9fdbf82cc748a2b9774"
        original_sha1 = "1e768d7f6c7229c0db5e17f636f203ee2e084f72"
        id = "158"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 53 70 6F 74 69 66 79 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }

    condition:
        $magic_bytes at 0
}


rule rule_159_EXE_2fb6c16c {
    meta:
        original_name = "File159"
        file_type = "EXE"
        file_size = 317088
        original_md5 = "2fb6c16c0f1c39d9ec32dbb311990b9c"
        original_sha1 = "dd56bde584ef1c333304c30f2cfa7311f576139a"
        id = "159"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 8B 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_160_EXE_5b88c51e {
    meta:
        original_name = "File160"
        file_type = "EXE"
        file_size = 4096
        original_md5 = "5b88c51ea10f9db362369f3d71bea569"
        original_sha1 = "bee2ed1bea54e7d00b1bd0d44d817406d74a2af3"
        id = "160"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_161_ZIP_c875c6cc {
    meta:
        original_name = "File161"
        file_type = "ZIP"
        file_size = 50971
        original_md5 = "c875c6cc8e2086011748fd6f9de83ff9"
        original_sha1 = "b75a7ca6961ffdcafd25f6b3b5a523a71b0fefc1"
        id = "161"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 CF 3E 7B 02 01 00 00 BB 02 00 00 0B 00 08 02 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 04 02 28 A0 00 02 00 }

    condition:
        $magic_bytes at 0
}


rule rule_162_ZIP_174c53b1 {
    meta:
        original_name = "File162"
        file_type = "ZIP"
        file_size = 28514
        original_md5 = "174c53b13bb9ddbdb1984108cf13e210"
        original_sha1 = "7be93d31bbb834fd3e1a0733d8d507ee168852a3"
        id = "162"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 A4 04 CF E9 71 01 00 00 98 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_163_JPEG_JFIF_0691b153 {
    meta:
        original_name = "File163"
        file_type = "JPEG_JFIF"
        file_size = 174733
        original_md5 = "0691b1534a7b7dfa1f311471d386d105"
        original_sha1 = "68623a4e28d08d0de4e03b9089981c77563d58ba"
        id = "163"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_164_EXE_f3dec47b {
    meta:
        original_name = "File164"
        file_type = "EXE"
        file_size = 12440
        original_md5 = "f3dec47bdc290fb01d5d908775321ea7"
        original_sha1 = "f0eefa4f62179cf8ed63de2d287512089e95a9be"
        id = "164"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_165_CUSTOM_UNKNOWN_BIN_1d786070 {
    meta:
        original_name = "File165"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 696
        original_md5 = "1d786070021811ce3d962a420d868155"
        original_sha1 = "6e09b863e9d2f5d7bdff1e2b2bd4e4afef7876dc"
        id = "165"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0D 0A 2E 53 59 4E 4F 50 53 49 53 0D 0A 20 20 20 20 20 20 20 20 49 6E 73 74 61 6C 6C 73 20 43 68 6F 63 6F 6C 61 74 65 79 20 28 6E 65 65 }

    condition:
        $magic_bytes at 0
}


rule rule_166_EXE_1af712a5 {
    meta:
        original_name = "File166"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "1af712a59ab34e0c131b40018d31c0f2"
        original_sha1 = "2c8951f8b0528ea9db00688cd76e14383ed0ed21"
        id = "166"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_167_CUSTOM_UNKNOWN_BIN_dfb1b490 {
    meta:
        original_name = "File167"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 1233
        original_md5 = "dfb1b490080d1aae0067e35550910c4d"
        original_sha1 = "d88c7c5224c1139118602158ad1d0217210780b0"
        id = "167"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 54 68 69 73 20 69 73 20 66 72 65 65 20 61 6E 64 20 75 6E 65 6E 63 75 6D 62 65 72 65 64 20 73 6F 66 74 77 61 72 65 20 72 65 6C 65 61 73 65 64 20 69 6E }

    condition:
        $magic_bytes at 0
}


rule rule_168_CUSTOM_UNKNOWN_BIN_cc46e3e9 {
    meta:
        original_name = "File168"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 7815
        original_md5 = "cc46e3e9ef97cbdc56318ee7ff23d73e"
        original_sha1 = "288f748f941f87169209eb1a058034c9a83e9b48"
        id = "168"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 4C 45 53 53 45 52 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 4E }

    condition:
        $magic_bytes at 0
}


rule rule_169_CUSTOM_UNKNOWN_BIN_d44a5415 {
    meta:
        original_name = "File169"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 781
        original_md5 = "d44a541590b9d5973136d0e595da9ae2"
        original_sha1 = "35c5bf4c4b20ff967dc35d6dd1ed79037f3189b8"
        id = "169"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 35 31 32 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A }

    condition:
        $magic_bytes at 0
}


rule rule_170_ZIP_fb9de5ec {
    meta:
        original_name = "File170"
        file_type = "ZIP"
        file_size = 6138710
        original_md5 = "fb9de5ec633240495f1ee57735839420"
        original_sha1 = "18771e2a544fdaffb6403aedf84b539f9d1fdb22"
        id = "170"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 C3 AA 5D 0E 8D 02 00 00 58 1D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_171_ZIP_19af6dc2 {
    meta:
        original_name = "File171"
        file_type = "ZIP"
        file_size = 1011368
        original_md5 = "19af6dc29171e27844e34c3c807231d9"
        original_sha1 = "976a891eb695b834305d28d287311793cf803222"
        id = "171"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 33 A5 4B 35 8A 01 00 00 99 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_172_CUSTOM_UNKNOWN_BIN_e322949a {
    meta:
        original_name = "File172"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 17097
        original_md5 = "e322949af834af9a143a29625e33a4e4"
        original_sha1 = "018baebf31f8635703aa99d8e66ee097760a46f8"
        id = "172"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 6F 7A 69 6C 6C 61 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 56 65 72 73 69 6F 6E 20 32 2E 30 0D 0A 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D }

    condition:
        $magic_bytes at 0
}


rule rule_173_EXE_3c555bd9 {
    meta:
        original_name = "File173"
        file_type = "EXE"
        file_size = 19232
        original_md5 = "3c555bd977fd395f0e3e0b3758071d52"
        original_sha1 = "06849f3bfb38b3b4aa5e2a0c0ac88734478bb9f7"
        id = "173"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_174_CUSTOM_UNKNOWN_BIN_a8dfc4d3 {
    meta:
        original_name = "File174"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 113
        original_md5 = "a8dfc4d3598873ff3fd86e28be66108f"
        original_sha1 = "474981497504ac58781039c01b9d3b32b18ed191"
        id = "174"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 61 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 30 30 0D 0A 73 65 74 20 2F 61 20 62 3D 25 72 61 6E }

    condition:
        $magic_bytes at 0
}


rule rule_175_CUSTOM_UNKNOWN_BIN_ec7522bc {
    meta:
        original_name = "File175"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 829
        original_md5 = "ec7522bc9873d8fb52d2dba4f19161ea"
        original_sha1 = "989ae95e6645c4f35a6326c1e69973954b2d75c8"
        id = "175"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 56 4C 43 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 73 20 50 }

    condition:
        $magic_bytes at 0
}


rule rule_176_EXE_6d8a087c {
    meta:
        original_name = "File176"
        file_type = "EXE"
        file_size = 3072
        original_md5 = "6d8a087c87e8c522ae0b7948357ee226"
        original_sha1 = "3001282ecd140d7120b94da8defcb02dbb26a8b0"
        id = "176"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_177_EXE_894e538f {
    meta:
        original_name = "File177"
        file_type = "EXE"
        file_size = 12064
        original_md5 = "894e538fbd29d9af2dac82abbb798aa8"
        original_sha1 = "3c28b3063ce80b3fd61e0afc6934e3180f5bef12"
        id = "177"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_178_CUSTOM_UNKNOWN_BIN_955ddefc {
    meta:
        original_name = "File178"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 608
        original_md5 = "955ddefc4f016045fb167016e499dd15"
        original_sha1 = "ecf760f19d07c912466db0f04b5bebb91cb07a22"
        id = "178"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 4E 65 74 66 6C 69 78 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }

    condition:
        $magic_bytes at 0
}


rule rule_179_CUSTOM_UNKNOWN_BIN_130668ab {
    meta:
        original_name = "File179"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 9093
        original_md5 = "130668abb2367024e10447831c36f700"
        original_sha1 = "6b0e6307e68f873cc4c01e3c9d02b61269784b85"
        id = "179"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4C 69 63 65 6E 73 65 20 32 2E 30 0D 0A 0D 0A 09 20 20 20 20 43 6F 70 79 72 69 67 68 }

    condition:
        $magic_bytes at 0
}


rule rule_180_EXE_6a9a905f {
    meta:
        original_name = "File180"
        file_type = "EXE"
        file_size = 2071847
        original_md5 = "6a9a905f16f64919e6892a2e8d37a5b7"
        original_sha1 = "faef2d937021c3ca367f275f0128b5ebaf50dbd8"
        id = "180"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_181_ZIP_cdc2e1b7 {
    meta:
        original_name = "File181"
        file_type = "ZIP"
        file_size = 9567
        original_md5 = "cdc2e1b7b617de1db19b5820fc9380a0"
        original_sha1 = "c19d042042cfe77f58ce28d55eca3f9741ba942c"
        id = "181"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 00 08 08 00 42 3D 3C 5A 47 92 44 B2 5A 01 00 00 F0 04 00 00 13 00 04 00 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 53 }

    condition:
        $magic_bytes at 0
}


rule rule_182_PDF_adc7a2cd {
    meta:
        original_name = "File182"
        file_type = "PDF"
        file_size = 490858
        original_md5 = "adc7a2cddbfa9080df9a9bce33153410"
        original_sha1 = "7774fd6a224c351c149d5db71d5c40fcfa762bf1"
        id = "182"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 34 0D 25 E2 E3 CF D3 0D 0A 31 32 31 33 20 30 20 6F 62 6A 0D 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 34 39 30 38 36 }

    condition:
        $magic_bytes at 0
}


rule rule_183_ZIP_5c4c9c4f {
    meta:
        original_name = "File183"
        file_type = "ZIP"
        file_size = 34148
        original_md5 = "5c4c9c4f71b373d50967fea0d9293b80"
        original_sha1 = "ed4ac6cf06a6828888f24b58416542dacf6e9960"
        id = "183"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 1C AD B2 D2 FA 01 00 00 6D 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_184_PNG_edf9fd64 {
    meta:
        original_name = "File184"
        file_type = "PNG"
        file_size = 1660287
        original_md5 = "edf9fd64840aca234a2cf40acd08026d"
        original_sha1 = "6faea83b19c6cbd392abe6df9c6fc0d10570d67b"
        id = "184"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD F9 8F 24 5B 96 }

    condition:
        $magic_bytes at 0
}


rule rule_185_ZIP_5b1392a9 {
    meta:
        original_name = "File185"
        file_type = "ZIP"
        file_size = 870117
        original_md5 = "5b1392a9f190a431ac6bac3b2f5be47c"
        original_sha1 = "b8fc3a4d1bb60155967dbf863b71ddd42148b1e0"
        id = "185"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 96 34 82 68 62 02 00 00 28 18 00 00 13 00 C5 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_186_CUSTOM_NULLPAD_cd58b486 {
    meta:
        original_name = "File186"
        file_type = "CUSTOM_NULLPAD"
        file_size = 2176
        original_md5 = "cd58b4860366a300cfb76a652d6e1dbf"
        original_sha1 = "1376127733d1bfb923dafc1aa0d47dcd078cd97e"
        id = "186"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 00 49 00 54 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 0D 00 0A 00 0D 00 0A 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 }

    condition:
        $magic_bytes at 0
}


rule rule_187_ZIP_77d26a68 {
    meta:
        original_name = "File187"
        file_type = "ZIP"
        file_size = 23570
        original_md5 = "77d26a68e9264e9facac4242de2e740f"
        original_sha1 = "028eee19afce5d914baec769287298cb9a3f8b8e"
        id = "187"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 F6 D3 96 8D 01 00 00 21 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_188_CUSTOM_UNKNOWN_BIN_ce174217 {
    meta:
        original_name = "File188"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 10470
        original_md5 = "ce1742175ff199f4d207ac4edc013419"
        original_sha1 = "c7324e8cca9b6ac3a39e2baaa564d52e13966a9f"
        id = "188"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4F 70 65 6E 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 28 22 4F 53 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 4F 70 65 6E 20 }

    condition:
        $magic_bytes at 0
}


rule rule_189_ZIP_38c425bf {
    meta:
        original_name = "File189"
        file_type = "ZIP"
        file_size = 95254
        original_md5 = "38c425bff814be81cacd15d2b4bcfeae"
        original_sha1 = "431f43d1284050f1a979a7260e72910213395704"
        id = "189"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 88 5E 62 0B CA 01 00 00 22 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_190_PNG_2ebe5a3b {
    meta:
        original_name = "File190"
        file_type = "PNG"
        file_size = 1799942
        original_md5 = "2ebe5a3b54f71e08d247aaacd9536fc7"
        original_sha1 = "aef536ba6dd1c9f499815a869340642f8a1a7d2a"
        id = "190"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B3 6D C7 75 }

    condition:
        $magic_bytes at 0
}


rule rule_191_ZIP_7c3c2be5 {
    meta:
        original_name = "File191"
        file_type = "ZIP"
        file_size = 148835
        original_md5 = "7c3c2be5d0f5bd562546cc8d03829aa4"
        original_sha1 = "ae984a2eebfad940599f7bc75bd60838d6d4eb2d"
        id = "191"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 58 79 36 07 DF 01 00 00 23 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_192_CUSTOM_NULLPAD_eb0293aa {
    meta:
        original_name = "File192"
        file_type = "CUSTOM_NULLPAD"
        file_size = 319563
        original_md5 = "eb0293aa9d3cd061798d7fe931dc5fa6"
        original_sha1 = "78642c9626ac9ca7e1812f397923b81a0adfabf2"
        id = "192"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_193_ZIP_a7f70b3e {
    meta:
        original_name = "File193"
        file_type = "ZIP"
        file_size = 466915
        original_md5 = "a7f70b3ec9911480be7dacbd1e37820d"
        original_sha1 = "420cc47965de6c73fe3065931d8d6fef01792ea2"
        id = "193"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0C 02 00 00 0C 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }

    condition:
        $magic_bytes at 0
}


rule rule_194_ZIP_44661e9d {
    meta:
        original_name = "File194"
        file_type = "ZIP"
        file_size = 1641870
        original_md5 = "44661e9d8e0b19cc4cdc71c58dac4595"
        original_sha1 = "355ed21d8da04a0ea27205b807979240fbefb356"
        id = "194"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3E 11 88 CA 60 02 00 00 47 19 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_195_CUSTOM_UNKNOWN_BIN_8581f7c7 {
    meta:
        original_name = "File195"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 87316
        original_md5 = "8581f7c7288375f14b8f164c83ea0ac9"
        original_sha1 = "3e38c02ce6df71a9aba792e89ea20beeb8032819"
        id = "195"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 71 4B 4E 12 05 02 00 00 EC 0C 00 00 13 00 CD 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_196_ZIP_3acb832c {
    meta:
        original_name = "File196"
        file_type = "ZIP"
        file_size = 1379663
        original_md5 = "3acb832c0b5bcd7df8cc140a771c612e"
        original_sha1 = "8e63f741347a04d664a023c6ec09c6c8ac99d327"
        id = "196"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 62 EE 9D 68 5E 01 00 00 90 04 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_197_ZIP_abfdce43 {
    meta:
        original_name = "File197"
        file_type = "ZIP"
        file_size = 2454899
        original_md5 = "abfdce4332a47d0056f54ecd5ff64e41"
        original_sha1 = "8ff3d262e9c83355e5c7ca3255c0688b53c6c983"
        id = "197"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 D2 41 75 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 68 65 61 64 65 72 31 2E 78 6D 6C A5 95 DB 8E }

    condition:
        $magic_bytes at 0
}


rule rule_198_ZIP_dd461e6b {
    meta:
        original_name = "File198"
        file_type = "ZIP"
        file_size = 10412619
        original_md5 = "dd461e6bc31f224519587dffd93048f8"
        original_sha1 = "93c63eb338cddb1cf2e23374e2bdebdf79302f4c"
        id = "198"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 99 55 7E 05 F9 00 00 00 E1 02 00 00 0B 00 F3 01 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 EF 01 28 A0 00 02 00 }

    condition:
        $magic_bytes at 0
}


rule rule_199_PDF_fd3900a6 {
    meta:
        original_name = "File199"
        file_type = "PDF"
        file_size = 266057
        original_md5 = "fd3900a6c106515c2db20b09720c7b3d"
        original_sha1 = "cf4cfbf3c7f8db99bedb4b58242b5a93f2e24408"
        id = "199"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0D 0A 25 B5 B5 B5 B5 0D 0A 31 20 30 20 6F 62 6A 0D 0A 3C 3C 2F 54 79 70 65 2F 43 61 74 61 6C 6F 67 2F 50 61 67 65 73 20 32 20 }

    condition:
        $magic_bytes at 0
}


rule rule_200_EXE_cb98f5f2 {
    meta:
        original_name = "File200"
        file_type = "EXE"
        file_size = 1543898
        original_md5 = "cb98f5f2982feefd5e6d9fca98bb7e39"
        original_sha1 = "c5c554b41d7005dafdbfc89c4f4b776331cabc48"
        id = "200"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 B3 64 49 92 1E 88 7D AA 6A 76 }

    condition:
        $magic_bytes at 0
}


rule rule_201_EXE_4e9a6f25 {
    meta:
        original_name = "File201"
        file_type = "EXE"
        file_size = 867014
        original_md5 = "4e9a6f255bff5ab93b6a7a51ebf62e99"
        original_sha1 = "f4baeceff5c949c66a85edcbf3ac40a774e3b887"
        id = "201"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_202_CUSTOM_NULLPAD_2497589c {
    meta:
        original_name = "File202"
        file_type = "CUSTOM_NULLPAD"
        file_size = 1204734
        original_md5 = "2497589c198a5c7d7c48f56bd5c2a083"
        original_sha1 = "f69b900367fa62e24947333fad2e4d8094002990"
        id = "202"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 42 00 02 00 00 00 20 00 00 00 FF FF 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 FB 71 6A 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_203_CUSTOM_UNKNOWN_BIN_80d158a5 {
    meta:
        original_name = "File203"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 781
        original_md5 = "80d158a5fce462fb2d54c71adc8e0da6"
        original_sha1 = "f0957d0ec699d079d4ad5adc73525925ce7ff829"
        id = "203"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 32 35 36 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A }

    condition:
        $magic_bytes at 0
}


rule rule_204_CUSTOM_UNKNOWN_BIN_d601a536 {
    meta:
        original_name = "File204"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 681
        original_md5 = "d601a536054abe2a84612a08b5b749f5"
        original_sha1 = "902f98265eb67fcd8d7da5eb0b8198071d887c85"
        id = "204"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 4F 42 53 20 53 74 75 64 69 6F 20 28 6E 65 65 64 73 20 61 64 6D 69 6E 20 }

    condition:
        $magic_bytes at 0
}


rule rule_205_JPEG_JFIF_eae001e9 {
    meta:
        original_name = "File205"
        file_type = "JPEG_JFIF"
        file_size = 169050
        original_md5 = "eae001e9a70c97bb5a2e6f17849c1d12"
        original_sha1 = "72cc668b05bac25159ee0198ce375b4358ab375c"
        id = "205"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_206_ZIP_16aa2764 {
    meta:
        original_name = "File206"
        file_type = "ZIP"
        file_size = 209333
        original_md5 = "16aa2764840ee306b4d60ed118ed642b"
        original_sha1 = "3b02a535fa7a2ccbe80d975f2b468de92dd3b8d5"
        id = "206"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 24 EC 50 BF 82 01 00 00 24 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_207_EXE_8c5c9499 {
    meta:
        original_name = "File207"
        file_type = "EXE"
        file_size = 726251
        original_md5 = "8c5c9499e5bf2515b46ad201e8340748"
        original_sha1 = "df382e06b0b50420b6d63240efe0681998fa8dfb"
        id = "207"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_208_ZIP_cb5e8db8 {
    meta:
        original_name = "File208"
        file_type = "ZIP"
        file_size = 3060289
        original_md5 = "cb5e8db8123b89323a4822992b5ddd34"
        original_sha1 = "b7d12ca8a56e690c38b3d2c82a3b52e138176b4f"
        id = "208"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E4 A7 B0 6F EB 01 00 00 35 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }

    condition:
        $magic_bytes at 0
}


rule rule_209_PDF_76909cea {
    meta:
        original_name = "File209"
        file_type = "PDF"
        file_size = 202653
        original_md5 = "76909cea13b5097b22a7faa800652758"
        original_sha1 = "fc407e7e35ab2470cc9228bacc41394a169a6fd5"
        id = "209"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 31 34 0A 2F }

    condition:
        $magic_bytes at 0
}


rule rule_210_ZIP_d23ddb02 {
    meta:
        original_name = "File210"
        file_type = "ZIP"
        file_size = 184563
        original_md5 = "d23ddb02acd5a876e306962bd71f1631"
        original_sha1 = "43db097d4df5012de9903c2de395a68147071827"
        id = "210"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 08 00 00 00 21 00 FC 1F ED 11 25 02 00 00 43 05 00 00 10 00 00 00 64 6F 63 50 72 6F 70 73 2F 61 70 70 2E 78 6D 6C 9C 54 DF 6F }

    condition:
        $magic_bytes at 0
}


rule rule_211_ZIP_c70ec8c6 {
    meta:
        original_name = "File211"
        file_type = "ZIP"
        file_size = 458026
        original_md5 = "c70ec8c66f59ecd212b7d08a4357b5d5"
        original_sha1 = "50b27cdf5ab5e9b9cc52a102fafae2c112403a1e"
        id = "211"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3B F4 79 E3 2E 03 00 00 B8 10 00 00 14 00 00 00 78 6C 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C EC }

    condition:
        $magic_bytes at 0
}


rule rule_212_CUSTOM_UNKNOWN_BIN_4a08c4bd {
    meta:
        original_name = "File212"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 182
        original_md5 = "4a08c4bd4d73b050f07c51d9d7192e57"
        original_sha1 = "df37ae666a00d846792533782a95b28b66d1320a"
        id = "212"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 61 64 76 69 63 65 3D 53 74 61 79 20 70 6F 73 69 74 69 76 65 2E 7C 54 61 6B 65 20 62 72 65 61 6B 73 2E 7C }

    condition:
        $magic_bytes at 0
}


rule rule_213_EXE_2a951f81 {
    meta:
        original_name = "File213"
        file_type = "EXE"
        file_size = 66043
        original_md5 = "2a951f81a38691f52fb9985513e46946"
        original_sha1 = "c79bf016e59f5a63697184e470304af54d1689da"
        id = "213"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic_bytes at 0
}


rule rule_214_JPEG_JFIF_3938baaa {
    meta:
        original_name = "File214"
        file_type = "JPEG_JFIF"
        file_size = 166868
        original_md5 = "3938baaa0bb6e35e2420178db164cb3d"
        original_sha1 = "03ad96e61cf716ff65919902d92c5cff197eee2f"
        id = "214"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_215_CUSTOM_UNKNOWN_BIN_ebc84c0b {
    meta:
        original_name = "File215"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 643
        original_md5 = "ebc84c0bae4a06d2db24c264d52dbb1f"
        original_sha1 = "d9c43a3c4df555360bf5e0eace9d2c04a5df74fd"
        id = "215"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 43 6F 64 65 0A 2E 44 45 53 43 }

    condition:
        $magic_bytes at 0
}


rule rule_216_CUSTOM_UNKNOWN_BIN_825341f9 {
    meta:
        original_name = "File216"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 628
        original_md5 = "825341f997632ff776e477883fe6493c"
        original_sha1 = "e9bfe5ea0889af5ed63d66a63b7b5b0861212ebb"
        id = "216"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 47 69 74 20 45 78 74 65 6E 73 69 6F 6E 73 0A 2E 44 45 53 43 52 49 50 54 }

    condition:
        $magic_bytes at 0
}


rule rule_217_CUSTOM_UNKNOWN_BIN_f1e7f2ec {
    meta:
        original_name = "File217"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 14118
        original_md5 = "f1e7f2ec19d0fd37d892e992a71fcbd6"
        original_sha1 = "5aa2bda8638878126e463b0f935a50d693bdbcee"
        id = "217"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 45 55 52 4F 50 45 41 4E 20 55 4E 49 4F 4E 20 50 55 42 4C 49 43 20 4C 49 43 45 4E 43 }

    condition:
        $magic_bytes at 0
}


rule rule_218_PNG_bb84661a {
    meta:
        original_name = "File218"
        file_type = "PNG"
        file_size = 1394042
        original_md5 = "bb84661af617931ba5b294a8737c421d"
        original_sha1 = "76a256f4ddd4584f562af45a06ba9952434d1671"
        id = "218"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 B0 6D C9 75 }

    condition:
        $magic_bytes at 0
}


rule rule_219_JPEG_JFIF_e87decf8 {
    meta:
        original_name = "File219"
        file_type = "JPEG_JFIF"
        file_size = 127189
        original_md5 = "e87decf883153221f84d73f70bb2f53b"
        original_sha1 = "043296334c60c14c8be4fce8b1a4bb962847581a"
        id = "219"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { FF D8 FF E0 00 10 45 58 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }

    condition:
        $magic_bytes at 0
}


rule rule_220_CUSTOM_UNKNOWN_BIN_db631805 {
    meta:
        original_name = "File220"
        file_type = "CUSTOM_UNKNOWN_BIN"
        file_size = 191
        original_md5 = "db631805541e0958fd9e6e3616a42c98"
        original_sha1 = "28b9d9f7b21ca28bf2b7e01f1da1f5a2080fe674"
        id = "220"
        detection_method = "HYBRID_SIGNATURE_AND_HASH"
        requires_hash_verification = "true"

    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 77 6F 72 64 3D 68 65 6C 6C 6F 0D 0A 73 65 74 20 73 63 72 61 6D 62 6C 65 64 3D 0D 0A 66 6F 72 20 2F 6C 20 }

    condition:
        $magic_bytes at 0
}
