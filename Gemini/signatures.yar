// NSSECU3 MP1 - Generated YARA Signatures
// Total Rules: 220


rule rule_001_EXE {
    meta:
        original_name = "File001"
        file_type = "EXE"
        target_size = 10768
        target_md5 = "7d0690a235298519fdc912928f0333ef"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_002_UNKNOWN {
    meta:
        original_name = "File002"
        file_type = "UNKNOWN"
        target_size = 556
        target_md5 = "e2142a946eca0ac74dd03fa1d9c67bd2"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 5A 6F 6F 6D 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 73 20 }
    condition:
        $magic_bytes at 0
}

rule rule_003_UNKNOWN {
    meta:
        original_name = "File003"
        file_type = "UNKNOWN"
        target_size = 1855
        target_md5 = "821094b7f221d9b915bbc55bc9530a1c"
    strings:
        $magic_bytes = { 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A 54 68 65 20 55 6E 69 76 65 72 73 61 6C 20 50 }
    condition:
        $magic_bytes at 0
}

rule rule_004_UNKNOWN {
    meta:
        original_name = "File004"
        file_type = "UNKNOWN"
        target_size = 149
        target_md5 = "6d30132c09d8e7feb13cd0fc951b8c67"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6C 69 6E 65 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 35 20 2B 20 31 0D 0A 66 6F 72 20 2F 66 20 22 }
    condition:
        $magic_bytes at 0
}

rule rule_005_EXE {
    meta:
        original_name = "File005"
        file_type = "EXE"
        target_size = 2560
        target_md5 = "8af314b532681aa2a272543e89bc1eeb"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_006_ZIP {
    meta:
        original_name = "File006"
        file_type = "ZIP"
        target_size = 4319474
        target_md5 = "17bbcf874c7ef4315dc7114f020c46e6"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 11 02 00 00 11 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_007_DOCX {
    meta:
        original_name = "File007"
        file_type = "DOCX"
        target_size = 1013332
        target_md5 = "9184f89abe4a76d7a312312396473c2c"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 D4 A2 46 3F D9 01 00 00 EC 09 00 00 13 00 D3 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_008_PNG {
    meta:
        original_name = "File008"
        file_type = "PNG"
        target_size = 1617304
        target_md5 = "75c7e160e5e35d778df5907c2c94dbd0"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 4C 45 4E 5A 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 79 9C 6D D9 75 }
    condition:
        $magic_bytes at 0
}

rule rule_009_PNG {
    meta:
        original_name = "File009"
        file_type = "PNG"
        target_size = 1726586
        target_md5 = "dcff3b11da469dab3029d65b9a9a026d"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 93 24 39 92 }
    condition:
        $magic_bytes at 0
}

rule rule_010_DOCX {
    meta:
        original_name = "File010"
        file_type = "DOCX"
        target_size = 4155280
        target_md5 = "df23a5f65a651a5368a1f4c68b4537fc"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3C F3 21 F4 57 02 00 00 9F 16 00 00 13 00 C0 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_011_ZIP {
    meta:
        original_name = "File011"
        file_type = "ZIP"
        target_size = 12996644
        target_md5 = "aa4fe812dc7a13e684d33bb70f3e4265"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0F 02 00 00 0F 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_012_DOCX {
    meta:
        original_name = "File012"
        file_type = "DOCX"
        target_size = 28659
        target_md5 = "cd7a8a6e473ca1693ae557da91650b8b"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 04 E8 63 06 F7 01 00 00 9B 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_013_UNKNOWN {
    meta:
        original_name = "File013"
        file_type = "UNKNOWN"
        target_size = 814
        target_md5 = "2d9a7072177dd37a9fbacbdaf12b8b35"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 4D 44 35 20 63 68 65 63 6B 73 75 6D 20 6F 66 20 61 20 66 69 6C 65 }
    condition:
        $magic_bytes at 0
}

rule rule_014_DOCX {
    meta:
        original_name = "File014"
        file_type = "DOCX"
        target_size = 3050393
        target_md5 = "79c0374c3dc8abfddac0c302d0330529"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E4 A7 B0 6F EB 01 00 00 35 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_015_UNKNOWN {
    meta:
        original_name = "File015"
        file_type = "UNKNOWN"
        target_size = 164
        target_md5 = "e4507f2ec05eb69d935540e5b4d7ec5e"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 75 6E 74 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 30 20 2B 20 31 0D 0A 65 63 68 6F 20 47 }
    condition:
        $magic_bytes at 0
}

rule rule_016_UNKNOWN {
    meta:
        original_name = "File016"
        file_type = "UNKNOWN"
        target_size = 87
        target_md5 = "e71bb959c29c164e77ae88bca85852d2"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 68 65 78 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 35 35 0D 0A 73 65 74 20 2F 61 20 68 65 78 32 }
    condition:
        $magic_bytes at 0
}

rule rule_017_ZIP {
    meta:
        original_name = "File017"
        file_type = "ZIP"
        target_size = 4810789
        target_md5 = "c374b2cac48b3b80144865fa7f181c2e"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0D 02 00 00 0D 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_018_PDF_1_5 {
    meta:
        original_name = "File018"
        file_type = "PDF-1.5"
        target_size = 407134
        target_md5 = "5bd7a1b4904acc6280e2c1924a627860"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 35 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 50 61 67 65 73 20 32 20 }
    condition:
        $magic_bytes at 0
}

rule rule_019_PNG {
    meta:
        original_name = "File019"
        file_type = "PNG"
        target_size = 1651234
        target_md5 = "9d5089314e21bb5001c52cb6228d9e0a"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 79 B0 25 D7 79 }
    condition:
        $magic_bytes at 0
}

rule rule_020_UNKNOWN {
    meta:
        original_name = "File020"
        file_type = "UNKNOWN"
        target_size = 38102
        target_md5 = "2452330b9f8f2c566f6b7c54d53c711a"
    strings:
        $magic_bytes = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6F 00 6E 00 20 00 34 00 2E 00 30 00 20 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 74 00 69 00 }
    condition:
        $magic_bytes at 0
}

rule rule_021_UNKNOWN {
    meta:
        original_name = "File021"
        file_type = "UNKNOWN"
        target_size = 35182
        target_md5 = "81936e46314e4a094681aa5a17eb0ed8"
    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 41 46 46 45 52 4F 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 }
    condition:
        $magic_bytes at 0
}

rule rule_022_PDF_1_7 {
    meta:
        original_name = "File022"
        file_type = "PDF-1.7"
        target_size = 185443
        target_md5 = "dc76bac39b0b05024c5dc4e167430170"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 50 61 67 65 73 20 32 20 30 20 52 0A 2F 54 79 70 65 20 2F 43 61 74 61 }
    condition:
        $magic_bytes at 0
}

rule rule_023_UNKNOWN {
    meta:
        original_name = "File023"
        file_type = "UNKNOWN"
        target_size = 686849
        target_md5 = "9c301375efa5c4613b55b7ae9178d837"
    strings:
        $magic_bytes = { 49 44 33 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_024_EXE {
    meta:
        original_name = "File024"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "371de9cf8b4b2520ab224038f0e6b9a5"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_025_EXE {
    meta:
        original_name = "File025"
        file_type = "EXE"
        target_size = 23832
        target_md5 = "0aca6a84b2b047abb36e3fb35b7938d3"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_026_UNKNOWN {
    meta:
        original_name = "File026"
        file_type = "UNKNOWN"
        target_size = 35821
        target_md5 = "4e5ec44fe5564450f9c1061ad18aeb38"
    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 4E 53 45 0D 0A 20 20 }
    condition:
        $magic_bytes at 0
}

rule rule_027_EXE {
    meta:
        original_name = "File027"
        file_type = "EXE"
        target_size = 3584
        target_md5 = "899c8ae4b45a7d4957468e47833bc84d"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_028_UNKNOWN {
    meta:
        original_name = "File028"
        file_type = "UNKNOWN"
        target_size = 109
        target_md5 = "3d809cda8a3b43c52a692d24e21af70b"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 64 69 65 31 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 36 20 2B 20 31 0D 0A 73 65 74 20 2F 61 20 64 }
    condition:
        $magic_bytes at 0
}

rule rule_029_UNKNOWN {
    meta:
        original_name = "File029"
        file_type = "UNKNOWN"
        target_size = 273
        target_md5 = "67571555f67b3a0b1cfb5b7efb8fa446"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 66 6F 72 20 2F 66 20 22 74 6F 6B 65 6E 73 3D 31 2D 34 20 64 65 6C 69 6D 73 3D 2F 20 22 20 25 25 61 20 69 6E 20 28 22 }
    condition:
        $magic_bytes at 0
}

rule rule_030_ZIP {
    meta:
        original_name = "File030"
        file_type = "ZIP"
        target_size = 5379567
        target_md5 = "da3fc8e4d769d1655552f9c000312c67"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 64 02 00 00 64 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_031_DOCX {
    meta:
        original_name = "File031"
        file_type = "DOCX"
        target_size = 59159
        target_md5 = "18ae60e913174c448c66c4bb674936e7"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 98 84 F0 A8 EB 01 00 00 22 0A 00 00 13 00 CA 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_032_DOCX {
    meta:
        original_name = "File032"
        file_type = "DOCX"
        target_size = 176259
        target_md5 = "93048e6c41c1e52a2be85096b8df6614"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E6 79 A3 97 BA 01 00 00 7D 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_033_UNKNOWN {
    meta:
        original_name = "File033"
        file_type = "UNKNOWN"
        target_size = 31332
        target_md5 = "8f037af809f60b33d6325be04e7e2747"
    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 AA F7 58 A4 79 01 00 00 14 06 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_034_UNKNOWN {
    meta:
        original_name = "File034"
        file_type = "UNKNOWN"
        target_size = 77
        target_md5 = "98c35c46893f75f22975e6c1ab6131e0"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6E 75 6D 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 30 30 30 30 0D 0A 65 63 68 6F 20 59 6F 75 72 }
    condition:
        $magic_bytes at 0
}

rule rule_035_DOCX {
    meta:
        original_name = "File035"
        file_type = "DOCX"
        target_size = 3097388
        target_md5 = "0c5393a75584590513c78674fa3f0d6f"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 00 00 08 00 00 00 21 00 61 0D D4 92 42 02 00 00 75 14 00 00 13 00 00 00 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C CC }
    condition:
        $magic_bytes at 0
}

rule rule_036_PNG {
    meta:
        original_name = "File036"
        file_type = "PNG"
        target_size = 1417519
        target_md5 = "a272e6b746211b62152db107c265ec14"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 B0 65 59 76 }
    condition:
        $magic_bytes at 0
}

rule rule_037_ZIP {
    meta:
        original_name = "File037"
        file_type = "ZIP"
        target_size = 266343
        target_md5 = "10c891b8ebc12cc4066af9a675d637e0"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 35 02 00 00 35 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_038_UNKNOWN {
    meta:
        original_name = "File038"
        file_type = "UNKNOWN"
        target_size = 5125758
        target_md5 = "ee65f859755a2a7aae846761cccad234"
    strings:
        $magic_bytes = { 43 44 30 30 31 2E 36 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 4D 65 74 61 64 61 74 61 20 32 20 30 20 52 0A 2F 4C 61 6E 67 20 28 65 6E }
    condition:
        $magic_bytes at 0
}

rule rule_039_UNKNOWN {
    meta:
        original_name = "File039"
        file_type = "UNKNOWN"
        target_size = 608
        target_md5 = "8f179f9b48d6c13fa96e801c31c5120b"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 44 69 73 63 6F 72 64 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }
    condition:
        $magic_bytes at 0
}

rule rule_040_UNKNOWN {
    meta:
        original_name = "File040"
        file_type = "UNKNOWN"
        target_size = 168
        target_md5 = "9ed8f42ccba544d90543e5f82e255fac"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 69 6E 70 75 74 3D 68 65 6C 6C 6F 0D 0A 73 65 74 20 72 65 76 65 72 73 65 64 3D 0D 0A 66 6F 72 20 2F 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_041_PNG {
    meta:
        original_name = "File041"
        file_type = "PNG"
        target_size = 1640375
        target_md5 = "6f821e51b6c6f33e1768187ddd1fba46"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 92 24 4B 92 }
    condition:
        $magic_bytes at 0
}

rule rule_042_EXE {
    meta:
        original_name = "File042"
        file_type = "EXE"
        target_size = 11280
        target_md5 = "74a4b714c851de93c773b1772a40807d"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_043_DOCX {
    meta:
        original_name = "File043"
        file_type = "DOCX"
        target_size = 106799
        target_md5 = "43e1b1fb5bcd16c937b0da2c4a6e540c"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 02 00 08 00 4A 24 76 59 FB 70 55 3B 11 53 00 00 49 4E 03 00 11 00 11 00 77 6F 72 64 2F 64 6F 63 75 6D 65 6E 74 2E 78 6D 6C 55 54 0D }
    condition:
        $magic_bytes at 0
}

rule rule_044_UNKNOWN {
    meta:
        original_name = "File044"
        file_type = "UNKNOWN"
        target_size = 229
        target_md5 = "58e6cf4d000a0330e09c022cf94f9be7"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 6C 6F 63 61 6C 20 65 6E 61 62 6C 65 64 65 6C 61 79 65 64 65 78 70 61 6E 73 69 6F 6E 0D 0A 73 65 74 20 77 6F }
    condition:
        $magic_bytes at 0
}

rule rule_045_JPEG_EXIF {
    meta:
        original_name = "File045"
        file_type = "JPEG-EXIF"
        target_size = 137878
        target_md5 = "6d8f6f9f0df51f804f0d9e706373d881"
    strings:
        $magic_bytes = { FF D8 FF E1 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_046_EXE {
    meta:
        original_name = "File046"
        file_type = "EXE"
        target_size = 80947
        target_md5 = "f63d16a402673307cbd7e0a69205baa4"
    strings:
        $magic_bytes = { 4D 5A 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_047_EXE {
    meta:
        original_name = "File047"
        file_type = "EXE"
        target_size = 1082258
        target_md5 = "130368dcac9cf8171b792bb164b1cd1c"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_048_UNKNOWN {
    meta:
        original_name = "File048"
        file_type = "UNKNOWN"
        target_size = 831
        target_md5 = "e117cf3498fa380b6c06de68232ee65a"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 31 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A 2E 44 }
    condition:
        $magic_bytes at 0
}

rule rule_049_UNKNOWN {
    meta:
        original_name = "File049"
        file_type = "UNKNOWN"
        target_size = 1804
        target_md5 = "428232826229b4484bd2a9de0091b60e"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 62 61 73 69 63 20 61 70 70 73 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A }
    condition:
        $magic_bytes at 0
}

rule rule_050_UNKNOWN {
    meta:
        original_name = "File050"
        file_type = "UNKNOWN"
        target_size = 86
        target_md5 = "c9ee034bbc5f70cc0246bde27c1be76f"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 6C 6F 72 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 36 0D 0A 63 6F 6C 6F 72 20 25 63 6F 6C }
    condition:
        $magic_bytes at 0
}

rule rule_051_EXE {
    meta:
        original_name = "File051"
        file_type = "EXE"
        target_size = 716249
        target_md5 = "db97870e110d2e495f191c432797ad04"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_052_JPEG_JFIF {
    meta:
        original_name = "File052"
        file_type = "JPEG-JFIF"
        target_size = 146273
        target_md5 = "a978b63e14d67b4d8a9625655adb3838"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_053_JPEG_JFIF {
    meta:
        original_name = "File053"
        file_type = "JPEG-JFIF"
        target_size = 173909
        target_md5 = "b7bbbb113e2913b4d54d17b47ec11308"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_054_UNKNOWN {
    meta:
        original_name = "File054"
        file_type = "UNKNOWN"
        target_size = 628
        target_md5 = "2c6444207e051dbb8f9f8ceb8f05bd06"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 47 69 74 20 66 6F 72 20 57 69 6E 64 6F 77 73 0A 2E 44 45 53 43 52 49 50 }
    condition:
        $magic_bytes at 0
}

rule rule_055_UNKNOWN {
    meta:
        original_name = "File055"
        file_type = "UNKNOWN"
        target_size = 844097
        target_md5 = "386812055de7c60fd297046a661ffd76"
    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 A9 90 C0 AD 7B 03 00 00 D3 10 00 00 14 00 00 00 70 70 74 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C }
    condition:
        $magic_bytes at 0
}

rule rule_056_ZIP {
    meta:
        original_name = "File056"
        file_type = "ZIP"
        target_size = 340390
        target_md5 = "1c03344f83275ac70b5391df2e8e0876"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF F3 01 00 00 F3 01 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_057_UNKNOWN {
    meta:
        original_name = "File057"
        file_type = "UNKNOWN"
        target_size = 691
        target_md5 = "7e40596c2d0399b64cc871ff4158ae57"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 45 6E 61 62 6C 65 73 20 74 68 65 20 67 6F 64 20 6D 6F 64 65 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E }
    condition:
        $magic_bytes at 0
}

rule rule_058_UNKNOWN {
    meta:
        original_name = "File058"
        file_type = "UNKNOWN"
        target_size = 23112
        target_md5 = "18039dade136470d4112c839cc043efe"
    strings:
        $magic_bytes = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }
    condition:
        $magic_bytes at 0
}

rule rule_059_PNG {
    meta:
        original_name = "File059"
        file_type = "PNG"
        target_size = 1720207
        target_md5 = "ebc5f89869f7306fe420ca02a9677f9f"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B3 6D 49 76 }
    condition:
        $magic_bytes at 0
}

rule rule_060_EXE {
    meta:
        original_name = "File060"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "8d404ac68cc517b456d0c46305caf6b4"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_061_UNKNOWN {
    meta:
        original_name = "File061"
        file_type = "UNKNOWN"
        target_size = 106
        target_md5 = "0a9bbaa0e74a6e389c73c1a18d9897ac"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 64 65 6C 61 79 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 35 20 2B 20 31 0D 0A 74 69 6D 65 6F 75 74 }
    condition:
        $magic_bytes at 0
}

rule rule_062_EXE {
    meta:
        original_name = "File062"
        file_type = "EXE"
        target_size = 11272
        target_md5 = "f0c3b5b14d0b5c1420d1e22f3585f4c3"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_063_UNKNOWN {
    meta:
        original_name = "File063"
        file_type = "UNKNOWN"
        target_size = 1962050
        target_md5 = "2b2cf30e60c4c5c6a7bfaf7f05f559b3"
    strings:
        $magic_bytes = { 49 44 33 31 2E 34 0D 25 80 84 88 8C 90 94 98 9C A0 A4 A8 AC B0 B4 B8 BC C0 C4 C8 CC D0 D4 D8 DC E0 E4 E8 EC F0 F4 F8 FC 0D 0D 31 20 30 20 6F 62 6A 0D }
    condition:
        $magic_bytes at 0
}

rule rule_064_UNKNOWN {
    meta:
        original_name = "File064"
        file_type = "UNKNOWN"
        target_size = 2138
        target_md5 = "ca807e6ce43369833704d96678d19667"
    strings:
        $magic_bytes = { 5B 4C 6F 63 61 6C 69 7A 65 64 46 69 6C 65 4E 61 6D 65 73 5D 0D 0A 62 69 6F 63 68 65 6D 5F 6D 65 64 2D 32 33 2D 32 2D 31 34 33 2D 33 2E 70 64 66 3D 40 }
    condition:
        $magic_bytes at 0
}

rule rule_065_UNKNOWN {
    meta:
        original_name = "File065"
        file_type = "UNKNOWN"
        target_size = 756
        target_md5 = "3ba7c71043ab870a87d59a781def60a5"
    strings:
        $magic_bytes = { 49 53 43 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A }
    condition:
        $magic_bytes at 0
}

rule rule_066_PDF_1_7 {
    meta:
        original_name = "File066"
        file_type = "PDF-1.7"
        target_size = 3259060
        target_md5 = "597122e0437a3753b00487694f30de80"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 36 20 30 20 6F 62 6A 0A 3C 3C 2F 46 69 6C 74 65 72 2F 46 6C 61 74 65 44 65 63 6F 64 65 2F 4C 65 6E 67 74 }
    condition:
        $magic_bytes at 0
}

rule rule_067_EXE {
    meta:
        original_name = "File067"
        file_type = "EXE"
        target_size = 366608
        target_md5 = "ea15bc1156bf638002b99c63bd4abb1a"
    strings:
        $magic_bytes = { 4D 5A 93 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_068_PNG {
    meta:
        original_name = "File068"
        file_type = "PNG"
        target_size = 1485481
        target_md5 = "4f81b658e6cc40fbf7c4664e14b24a29"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 AF 24 4B 92 }
    condition:
        $magic_bytes at 0
}

rule rule_069_PNG {
    meta:
        original_name = "File069"
        file_type = "PNG"
        target_size = 170993
        target_md5 = "314de58ba4408e243fc5e7f691014c26"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B }
    condition:
        $magic_bytes at 0
}

rule rule_070_PNG {
    meta:
        original_name = "File070"
        file_type = "PNG"
        target_size = 1645439
        target_md5 = "4effb217ca55d93bb55192693ef0ee9c"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 49 B3 65 4B 76 }
    condition:
        $magic_bytes at 0
}

rule rule_071_EXE {
    meta:
        original_name = "File071"
        file_type = "EXE"
        target_size = 11792
        target_md5 = "08422e540f71afbf8895440dbce80aa4"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_072_PNG {
    meta:
        original_name = "File072"
        file_type = "PNG"
        target_size = 1655833
        target_md5 = "5956a153b3144e3256047ab8eead83e5"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 97 25 C9 71 }
    condition:
        $magic_bytes at 0
}

rule rule_073_JPEG_JFIF {
    meta:
        original_name = "File073"
        file_type = "JPEG-JFIF"
        target_size = 157801
        target_md5 = "614cf260d4d13d5ffb6f947cc806d671"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_074_ZIP {
    meta:
        original_name = "File074"
        file_type = "ZIP"
        target_size = 7213107
        target_md5 = "f9b2c6c68a3ddfc2678fcd9f0cf0464e"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 2D 02 00 00 2D 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_075_EXE {
    meta:
        original_name = "File075"
        file_type = "EXE"
        target_size = 341331
        target_md5 = "cbf27b79169a22e2ed9f2f6ded176cdb"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_076_DOCX {
    meta:
        original_name = "File076"
        file_type = "DOCX"
        target_size = 115731
        target_md5 = "585ce4469a6adfebb17e5c7b1163f349"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 AB 0B 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 68 65 61 64 65 72 31 2E 78 6D 6C CD 96 DB 8E }
    condition:
        $magic_bytes at 0
}

rule rule_077_UNKNOWN {
    meta:
        original_name = "File077"
        file_type = "UNKNOWN"
        target_size = 603
        target_md5 = "f5fa09dace753bebba5b6075f127dc26"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 43 68 72 6F 6D 65 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 }
    condition:
        $magic_bytes at 0
}

rule rule_078_JPEG_JFIF {
    meta:
        original_name = "File078"
        file_type = "JPEG-JFIF"
        target_size = 160610
        target_md5 = "2431f8e75577a0e57896d66782cb9890"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_079_UNKNOWN {
    meta:
        original_name = "File079"
        file_type = "UNKNOWN"
        target_size = 339655
        target_md5 = "b6167a060ce70bcc90de22e27a3fbb07"
    strings:
        $magic_bytes = { FF FB 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_080_EXE {
    meta:
        original_name = "File080"
        file_type = "EXE"
        target_size = 11792
        target_md5 = "12961a8d12e77fc9b66345b80456f7fe"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_081_EXE {
    meta:
        original_name = "File081"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "52376b5fbaa7a368612ca909730cf9b3"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_082_UNKNOWN {
    meta:
        original_name = "File082"
        file_type = "UNKNOWN"
        target_size = 147
        target_md5 = "559dd7a83d0d7688e334978e75d45beb"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 70 61 74 68 73 3D 43 3A 5C 57 69 6E 64 6F 77 73 5C 20 43 3A 5C 55 73 65 72 73 5C 20 43 3A 5C 50 72 6F 67 }
    condition:
        $magic_bytes at 0
}

rule rule_083_UNKNOWN {
    meta:
        original_name = "File083"
        file_type = "UNKNOWN"
        target_size = 124
        target_md5 = "d324ff068ad2ee0ce710cfe951697116"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 6E 75 6D 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 36 20 2B 20 36 35 0D 0A 66 6F 72 20 2F 66 20 }
    condition:
        $magic_bytes at 0
}

rule rule_084_PDF_1_3 {
    meta:
        original_name = "File084"
        file_type = "PDF-1.3"
        target_size = 417316
        target_md5 = "0003f23eb36cf0145bb82e108295b143"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 33 33 0A 2F }
    condition:
        $magic_bytes at 0
}

rule rule_085_ZIP {
    meta:
        original_name = "File085"
        file_type = "ZIP"
        target_size = 406205
        target_md5 = "5a237806a6afec0a40fb433530387001"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 CF 3E 7B 02 01 00 00 BB 02 00 00 0B 00 ED 01 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 E9 01 28 A0 00 02 00 }
    condition:
        $magic_bytes at 0
}

rule rule_086_UNKNOWN {
    meta:
        original_name = "File086"
        file_type = "UNKNOWN"
        target_size = 677
        target_md5 = "6130cc3a7797bd20785db9a1e38246bc"
    strings:
        $magic_bytes = { 42 53 44 20 5A 65 72 6F 20 43 6C 61 75 73 65 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 }
    condition:
        $magic_bytes at 0
}

rule rule_087_DOCX {
    meta:
        original_name = "File087"
        file_type = "DOCX"
        target_size = 288249
        target_md5 = "b4ea3fa8c44c0e05e86e4b0d8859cf0f"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 8F BF F1 36 23 04 00 00 C5 4E 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_088_UNKNOWN {
    meta:
        original_name = "File088"
        file_type = "UNKNOWN"
        target_size = 100
        target_md5 = "822123f73ba273c1a622f5d5cf32633b"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 66 6F 72 20 2F 6C 20 25 25 69 20 69 6E 20 28 31 2C 31 2C 33 32 29 20 64 6F 20 28 0D 0A 20 20 20 20 73 65 74 20 2F 61 }
    condition:
        $magic_bytes at 0
}

rule rule_089_JPEG_JFIF {
    meta:
        original_name = "File089"
        file_type = "JPEG-JFIF"
        target_size = 180248
        target_md5 = "905363c4abd5f39bc6f98ff3e25b0281"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_090_JPEG_JFIF {
    meta:
        original_name = "File090"
        file_type = "JPEG-JFIF"
        target_size = 169745
        target_md5 = "3e736f0149faed08b112e43245750aa8"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_091_UNKNOWN {
    meta:
        original_name = "File091"
        file_type = "UNKNOWN"
        target_size = 494
        target_md5 = "00cf085bfe51c5de71ff776ac8257e34"
    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 44 4F 20 57 48 41 54 20 54 48 45 20 46 55 43 4B 20 59 4F 55 20 57 41 4E 54 20 54 4F 20 50 55 42 4C 49 43 20 4C 49 }
    condition:
        $magic_bytes at 0
}

rule rule_092_EXE {
    meta:
        original_name = "File092"
        file_type = "EXE"
        target_size = 412847
        target_md5 = "cb22ec32b6b7d83582b7fda7d682ff89"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_093_DOCX {
    meta:
        original_name = "File093"
        file_type = "DOCX"
        target_size = 3038333
        target_md5 = "8a0b5139a1e35f636b28893cb6436fb9"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9D 7C 73 2A E3 01 00 00 B5 0C 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_094_DOCX {
    meta:
        original_name = "File094"
        file_type = "DOCX"
        target_size = 62950
        target_md5 = "d46229b61ac5fa694f1e5547d7cf424e"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 81 71 7D 3C F8 01 00 00 BA 0C 00 00 13 00 CD 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_095_EXE {
    meta:
        original_name = "File095"
        file_type = "EXE"
        target_size = 259805
        target_md5 = "bb24a4f283eeeb0a5b6a63256e197fad"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_096_DOCX {
    meta:
        original_name = "File096"
        file_type = "DOCX"
        target_size = 187180
        target_md5 = "6b8f2e87dfddec9238fb7252e63ad558"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 D5 71 95 3E E1 01 00 00 7A 09 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_097_UNKNOWN {
    meta:
        original_name = "File097"
        file_type = "UNKNOWN"
        target_size = 132678
        target_md5 = "d9b96769f85876192c5efcfa556ab7f4"
    strings:
        $magic_bytes = { FF D9 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_098_PNG {
    meta:
        original_name = "File098"
        file_type = "PNG"
        target_size = 1684054
        target_md5 = "e23a82888ff953e592c9935f447348e7"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 AC 6D DB 75 }
    condition:
        $magic_bytes at 0
}

rule rule_099_UNKNOWN {
    meta:
        original_name = "File099"
        file_type = "UNKNOWN"
        target_size = 352
        target_md5 = "492b46063a1fa97a738da1a411aad4d1"
    strings:
        $magic_bytes = { 0A 22 31 2E 20 49 6E 73 74 61 6C 6C 20 61 6E 64 20 63 6F 6E 66 69 67 75 72 65 20 74 68 65 20 6E 65 63 65 73 73 61 72 79 20 64 65 70 65 6E 64 65 6E 63 }
    condition:
        $magic_bytes at 0
}

rule rule_100_DOCX {
    meta:
        original_name = "File100"
        file_type = "DOCX"
        target_size = 27963
        target_md5 = "95b6f67c991027de4266a1e0e7e8d527"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 1E 27 60 70 88 01 00 00 AE 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_101_EXE {
    meta:
        original_name = "File101"
        file_type = "EXE"
        target_size = 12816
        target_md5 = "b022e52fae3ea7da7b43c8e80ca646a9"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_102_UNKNOWN {
    meta:
        original_name = "File102"
        file_type = "UNKNOWN"
        target_size = 196042
        target_md5 = "63acfbba8e6e6dfba235018deaad7ab6"
    strings:
        $magic_bytes = { 52 49 46 46 57 41 56 45 2D 31 2E 36 0D 25 E2 E3 CF D3 0D 0A 35 39 20 30 20 6F 62 6A 20 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 31 39 36 }
    condition:
        $magic_bytes at 0
}

rule rule_103_PDF_1_4 {
    meta:
        original_name = "File103"
        file_type = "PDF-1.4"
        target_size = 7474390
        target_md5 = "1f6d1bba0572b67079ce8b19f66377f4"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 34 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 56 65 72 73 69 6F 6E 20 }
    condition:
        $magic_bytes at 0
}

rule rule_104_DOCX {
    meta:
        original_name = "File104"
        file_type = "DOCX"
        target_size = 1286316
        target_md5 = "315c12e381824fa8187634f37e4d12da"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 2B 54 51 0E D9 02 00 00 A6 24 00 00 13 00 BA 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_105_PNG {
    meta:
        original_name = "File105"
        file_type = "PNG"
        target_size = 1426547
        target_md5 = "2e8f9dd9eacb56032b79a06250e949a6"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD F9 93 24 5B 76 }
    condition:
        $magic_bytes at 0
}

rule rule_106_UNKNOWN {
    meta:
        original_name = "File106"
        file_type = "UNKNOWN"
        target_size = 28944
        target_md5 = "fe975f7601a2126ba0431d2e84cb71d8"
    strings:
        $magic_bytes = { 45 00 63 00 6C 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6C 00 69 00 63 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 20 00 2D 00 20 00 }
    condition:
        $magic_bytes at 0
}

rule rule_107_JPEG_JFIF {
    meta:
        original_name = "File107"
        file_type = "JPEG-JFIF"
        target_size = 142129
        target_md5 = "62b5f962ab419a0e7d39693a47f6f8cf"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_108_PNG {
    meta:
        original_name = "File108"
        file_type = "PNG"
        target_size = 1544836
        target_md5 = "2083b7845475c50f4d3d0ce43abddf47"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B2 2C 49 92 }
    condition:
        $magic_bytes at 0
}

rule rule_109_UNKNOWN {
    meta:
        original_name = "File109"
        file_type = "UNKNOWN"
        target_size = 556987
        target_md5 = "a8db5b9ff83ebe7e87a3971576158977"
    strings:
        $magic_bytes = { 52 49 46 46 57 41 56 45 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 }
    condition:
        $magic_bytes at 0
}

rule rule_110_UNKNOWN {
    meta:
        original_name = "File110"
        file_type = "UNKNOWN"
        target_size = 2828
        target_md5 = "8b17d3c1a890583d649554e66df1c9e6"
    strings:
        $magic_bytes = { 4D 69 63 72 6F 73 6F 66 74 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 28 4D 73 2D 50 4C 29 0D 0A 0D 0A 54 68 69 73 20 6C 69 63 65 6E 73 65 20 67 }
    condition:
        $magic_bytes at 0
}

rule rule_111_DOCX {
    meta:
        original_name = "File111"
        file_type = "DOCX"
        target_size = 146438
        target_md5 = "bbfd94f750618d4eb4fc8c3d6a9ff11d"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 45 8C 02 3A BC 01 00 00 64 08 00 00 13 00 DC 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_112_UNKNOWN {
    meta:
        original_name = "File112"
        file_type = "UNKNOWN"
        target_size = 41
        target_md5 = "c75dbb43150fd2ce4732c77ef9997def"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 65 63 68 6F 20 52 61 6E 64 6F 6D 20 53 74 72 69 6E 67 3A 20 25 72 61 6E 64 6F 6D 25 0D 0A }
    condition:
        $magic_bytes at 0
}

rule rule_113_JPEG_JFIF {
    meta:
        original_name = "File113"
        file_type = "JPEG-JFIF"
        target_size = 160547
        target_md5 = "8019c9631f622de19c81a3e19df8b4ed"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_114_PDF_1_3 {
    meta:
        original_name = "File114"
        file_type = "PDF-1.3"
        target_size = 527117
        target_md5 = "9b702a3a329410a22d2877816ece84c5"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 32 30 0A 2F }
    condition:
        $magic_bytes at 0
}

rule rule_115_EXE {
    meta:
        original_name = "File115"
        file_type = "EXE"
        target_size = 1063014
        target_md5 = "9e25484b1907186fa37395a4c3b79940"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_116_DOCX {
    meta:
        original_name = "File116"
        file_type = "DOCX"
        target_size = 694240
        target_md5 = "b153dc51097eaf6bc297727b41d16fa9"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 74 76 54 0C D0 01 00 00 6C 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_117_DOCX {
    meta:
        original_name = "File117"
        file_type = "DOCX"
        target_size = 64531
        target_md5 = "0d7783aa3a521e6d64aa1a829c5ea90a"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9C BD 3C E3 CE 01 00 00 C4 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_118_EXE {
    meta:
        original_name = "File118"
        file_type = "EXE"
        target_size = 1080656
        target_md5 = "e729b5cc0ca22d973378a595f0c02cf8"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_119_UNKNOWN {
    meta:
        original_name = "File119"
        file_type = "UNKNOWN"
        target_size = 555
        target_md5 = "fdea5ae8a8ede952bc58bdb26b47d57a"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 54 77 69 74 74 65 72 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }
    condition:
        $magic_bytes at 0
}

rule rule_120_UNKNOWN {
    meta:
        original_name = "File120"
        file_type = "UNKNOWN"
        target_size = 572
        target_md5 = "0f3ee7c9eb9340ae44a93bfcd27523ba"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 54 68 75 6E 64 65 72 62 69 72 64 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E }
    condition:
        $magic_bytes at 0
}

rule rule_121_DOCX {
    meta:
        original_name = "File121"
        file_type = "DOCX"
        target_size = 345850
        target_md5 = "78db5fb8d3b5f11d349384c5c808d94c"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 9F 04 C7 C5 38 02 00 00 54 10 00 00 13 00 C2 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_122_DOCX {
    meta:
        original_name = "File122"
        file_type = "DOCX"
        target_size = 572074
        target_md5 = "423e0563fe719395891fa51a000a41ad"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 48 A5 75 59 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 77 6F 72 64 2F 6E 75 6D 62 65 72 69 6E 67 2E 78 6D 6C ED 9B }
    condition:
        $magic_bytes at 0
}

rule rule_123_PDF_1_5 {
    meta:
        original_name = "File123"
        file_type = "PDF-1.5"
        target_size = 521414
        target_md5 = "bd0ea60d14eea5566361109dc08af4ae"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 35 0D 0A 25 B5 B5 B5 B5 0D 0A 31 20 30 20 6F 62 6A 0D 0A 3C 3C 2F 54 79 70 65 2F 43 61 74 61 6C 6F 67 2F 50 61 67 65 73 20 32 20 }
    condition:
        $magic_bytes at 0
}

rule rule_124_JPEG_JFIF {
    meta:
        original_name = "File124"
        file_type = "JPEG-JFIF"
        target_size = 173180
        target_md5 = "d2183bc6bc61647833e480df21079df5"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_125_PNG {
    meta:
        original_name = "File125"
        file_type = "PNG"
        target_size = 1591997
        target_md5 = "b4eb8e22a873e2bff9a2c056c20da979"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 67 B4 65 C9 75 }
    condition:
        $magic_bytes at 0
}

rule rule_126_PNG {
    meta:
        original_name = "File126"
        file_type = "PNG"
        target_size = 1502871
        target_md5 = "eff3a759ab08c2c95fdba8c3cde7c1f8"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 77 B0 25 C9 79 }
    condition:
        $magic_bytes at 0
}

rule rule_127_JPEG_JFIF {
    meta:
        original_name = "File127"
        file_type = "JPEG-JFIF"
        target_size = 154510
        target_md5 = "07167ed9288a6fb574bbb0ad229bf1b0"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_128_UNKNOWN {
    meta:
        original_name = "File128"
        file_type = "UNKNOWN"
        target_size = 87
        target_md5 = "c79e9121e51d9373a410b53ae8a3d964"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 63 6F 64 65 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 32 35 35 0D 0A 65 63 68 6F 20 45 78 69 74 69 }
    condition:
        $magic_bytes at 0
}

rule rule_129_PDF_1_3 {
    meta:
        original_name = "File129"
        file_type = "PDF-1.3"
        target_size = 217395
        target_md5 = "321ae2c8ccc6a16073c16910ec598891"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 31 39 0A 2F }
    condition:
        $magic_bytes at 0
}

rule rule_130_DOCX {
    meta:
        original_name = "File130"
        file_type = "DOCX"
        target_size = 100153
        target_md5 = "1e40fe728f54ab560be84048b37e2136"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3D 57 87 34 C6 01 00 00 BF 08 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_131_DOCX {
    meta:
        original_name = "File131"
        file_type = "DOCX"
        target_size = 26769
        target_md5 = "ec026d8ed4a1aeaeca8eeb4e7bd17715"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 A6 74 04 52 85 01 00 00 AC 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_132_PDF_1_6 {
    meta:
        original_name = "File132"
        file_type = "PDF-1.6"
        target_size = 588152
        target_md5 = "d0787c3ca7aab644472e1a015c23597c"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 36 0D 25 E2 E3 CF D3 0D 0A 34 33 31 20 30 20 6F 62 6A 0D 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 35 38 38 31 35 32 }
    condition:
        $magic_bytes at 0
}

rule rule_133_JPEG_JFIF {
    meta:
        original_name = "File133"
        file_type = "JPEG-JFIF"
        target_size = 159149
        target_md5 = "89e432c568ecd36d5136ce58c923eb9a"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_134_DOCX {
    meta:
        original_name = "File134"
        file_type = "DOCX"
        target_size = 744699
        target_md5 = "d6eadec77ea7a7436fb9e5f39bdc9b36"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3D 57 87 34 C6 01 00 00 BF 08 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_135_PDF_1_7 {
    meta:
        original_name = "File135"
        file_type = "PDF-1.7"
        target_size = 5765224
        target_md5 = "14ca718fd2c6718e4a31472da950627a"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0D 25 E2 E3 CF D3 0D 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 41 63 72 6F 46 6F 72 6D 20 35 20 30 20 52 2F 4C 61 6E 67 28 65 6E 29 }
    condition:
        $magic_bytes at 0
}

rule rule_136_UNKNOWN {
    meta:
        original_name = "File136"
        file_type = "UNKNOWN"
        target_size = 1809714
        target_md5 = "31bbd83292460bdfb30a7bd9ff9aaf4b"
    strings:
        $magic_bytes = { 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 5B B3 24 49 92 1E 88 7D AA 66 EE 1E 71 }
    condition:
        $magic_bytes at 0
}

rule rule_137_UNKNOWN {
    meta:
        original_name = "File137"
        file_type = "UNKNOWN"
        target_size = 1359
        target_md5 = "81543b22c36f10d20ac9712f8d80ef8d"
    strings:
        $magic_bytes = { 42 6F 6F 73 74 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 2D 20 56 65 72 73 69 6F 6E 20 31 2E 30 20 2D 20 41 75 67 75 73 74 20 31 37 74 68 }
    condition:
        $magic_bytes at 0
}

rule rule_138_PDF_1_7 {
    meta:
        original_name = "File138"
        file_type = "PDF-1.7"
        target_size = 663177
        target_md5 = "302b502d4e62ce9364d06014e544c095"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 2F 43 6F 6C 6F 72 53 70 61 63 65 2F 44 65 76 69 63 65 47 72 61 79 2F 53 75 }
    condition:
        $magic_bytes at 0
}

rule rule_139_UNKNOWN {
    meta:
        original_name = "File139"
        file_type = "UNKNOWN"
        target_size = 168
        target_md5 = "0618ec59c2401e95bc66f5f48bb46bdc"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 73 65 6E 74 65 6E 63 65 73 3D 48 65 6C 6C 6F 7C 48 6F 77 20 61 72 65 20 79 6F 75 3F 7C 4E 69 63 65 20 77 }
    condition:
        $magic_bytes at 0
}

rule rule_140_JPEG_JFIF {
    meta:
        original_name = "File140"
        file_type = "JPEG-JFIF"
        target_size = 157962
        target_md5 = "f83e3fd9b34363578c2128dc3eac6f01"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_141_EXE {
    meta:
        original_name = "File141"
        file_type = "EXE"
        target_size = 472874
        target_md5 = "ac1b94145d5bf11f34eba1137d8b39e2"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_142_PPTX {
    meta:
        original_name = "File142"
        file_type = "PPTX"
        target_size = 2693126
        target_md5 = "ecf92b48eaa6ff7d658170aa49a6e660"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 08 00 00 00 21 00 03 E4 7B FE C7 03 00 00 91 13 00 00 14 00 00 00 70 70 74 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C }
    condition:
        $magic_bytes at 0
}

rule rule_143_JPEG {
    meta:
        original_name = "File143"
        file_type = "JPEG"
        target_size = 1635658
        target_md5 = "cef114c5875ba465fbdcb7dc7b297a42"
    strings:
        $magic_bytes = { FF D8 FF 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 93 24 49 92 26 88 7D CC 22 }
    condition:
        $magic_bytes at 0
}

rule rule_144_ZIP {
    meta:
        original_name = "File144"
        file_type = "ZIP"
        target_size = 2490902
        target_md5 = "d19b96636f75b86f0f2740e6434e7b6f"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 1C 02 00 00 1C 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_145_DOCX {
    meta:
        original_name = "File145"
        file_type = "DOCX"
        target_size = 82840
        target_md5 = "d688f330a67743da9edf360bd87a4757"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 FF BF 18 7A 2E 02 00 00 57 0D 00 00 13 00 C2 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_146_EXE {
    meta:
        original_name = "File146"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "290a44f94f15d6ae35915320294947f6"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_147_UNKNOWN {
    meta:
        original_name = "File147"
        file_type = "UNKNOWN"
        target_size = 156
        target_md5 = "a4da80722c9b88f6fd9261637af70098"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 6D 65 73 73 61 67 65 3D 4C 6F 61 64 69 6E 67 20 72 61 6E 64 6F 6D 20 74 65 78 74 2E 2E 2E 0D 0A 66 6F 72 }
    condition:
        $magic_bytes at 0
}

rule rule_148_UNKNOWN {
    meta:
        original_name = "File148"
        file_type = "UNKNOWN"
        target_size = 315392
        target_md5 = "ef063d467563865aa7a97b4dae9924ce"
    strings:
        $magic_bytes = { FF FB 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_149_DOCX {
    meta:
        original_name = "File149"
        file_type = "DOCX"
        target_size = 27228
        target_md5 = "0a35b9503060597bb052f21b4b4290d6"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 CE 13 76 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 66 6F 6F 74 65 72 31 2E 78 6D 6C ED 57 FF 6E }
    condition:
        $magic_bytes at 0
}

rule rule_150_ZIP {
    meta:
        original_name = "File150"
        file_type = "ZIP"
        target_size = 955283
        target_md5 = "4cc3cee04f7e695a8de8591e15f19fc1"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 20 02 00 00 20 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_151_DOCX {
    meta:
        original_name = "File151"
        file_type = "DOCX"
        target_size = 4723372
        target_md5 = "c0e566ec23e885ddeb11e5a4070fb841"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B7 BB C7 DC A4 02 00 00 00 25 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_152_JPEG_JFIF {
    meta:
        original_name = "File152"
        file_type = "JPEG-JFIF"
        target_size = 151135
        target_md5 = "d647f67138863d8bf85b246774392709"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_153_XLSX {
    meta:
        original_name = "File153"
        file_type = "XLSX"
        target_size = 40590
        target_md5 = "07b039a576b247f2719d7c1372e7d1c7"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 BA BB 75 55 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 78 6C 2F 63 6F 6D 6D 65 6E 74 73 31 2E 78 6D 6C 8D 53 CB 6E }
    condition:
        $magic_bytes at 0
}

rule rule_154_UNKNOWN {
    meta:
        original_name = "File154"
        file_type = "UNKNOWN"
        target_size = 22534
        target_md5 = "a1c1ccba318f1630f5ffbdca6cdd12b2"
    strings:
        $magic_bytes = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6F 00 6E 00 61 00 6C 00 20 00 43 00 6F 00 6D 00 6D 00 75 00 6E 00 69 00 74 00 79 00 20 00 4C 00 69 00 63 00 }
    condition:
        $magic_bytes at 0
}

rule rule_155_EXE {
    meta:
        original_name = "File155"
        file_type = "EXE"
        target_size = 301568
        target_md5 = "774faa35314ccf72d1b9d841b4532b03"
    strings:
        $magic_bytes = { 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_156_PDF_1_7 {
    meta:
        original_name = "File156"
        file_type = "PDF-1.7"
        target_size = 347444
        target_md5 = "8e984f349c1855d2ac331a822f548ddd"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67 0A 2F 50 61 67 65 73 20 32 20 }
    condition:
        $magic_bytes at 0
}

rule rule_157_UNKNOWN {
    meta:
        original_name = "File157"
        file_type = "UNKNOWN"
        target_size = 10483
        target_md5 = "362889c21e1a9f7404c13205ea1b9fde"
    strings:
        $magic_bytes = { 41 63 61 64 65 6D 69 63 20 46 72 65 65 20 4C 69 63 65 6E 73 65 20 28 22 41 46 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 41 63 61 64 65 }
    condition:
        $magic_bytes at 0
}

rule rule_158_UNKNOWN {
    meta:
        original_name = "File158"
        file_type = "UNKNOWN"
        target_size = 631
        target_md5 = "5eba08d45abbd9fdbf82cc748a2b9774"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 53 70 6F 74 69 66 79 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }
    condition:
        $magic_bytes at 0
}

rule rule_159_EXE {
    meta:
        original_name = "File159"
        file_type = "EXE"
        target_size = 317088
        target_md5 = "2fb6c16c0f1c39d9ec32dbb311990b9c"
    strings:
        $magic_bytes = { 4D 5A 8B 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_160_EXE {
    meta:
        original_name = "File160"
        file_type = "EXE"
        target_size = 4096
        target_md5 = "5b88c51ea10f9db362369f3d71bea569"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_161_ZIP {
    meta:
        original_name = "File161"
        file_type = "ZIP"
        target_size = 50971
        target_md5 = "c875c6cc8e2086011748fd6f9de83ff9"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 CF 3E 7B 02 01 00 00 BB 02 00 00 0B 00 08 02 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 04 02 28 A0 00 02 00 }
    condition:
        $magic_bytes at 0
}

rule rule_162_DOCX {
    meta:
        original_name = "File162"
        file_type = "DOCX"
        target_size = 28514
        target_md5 = "174c53b13bb9ddbdb1984108cf13e210"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 A4 04 CF E9 71 01 00 00 98 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_163_JPEG_JFIF {
    meta:
        original_name = "File163"
        file_type = "JPEG-JFIF"
        target_size = 174733
        target_md5 = "0691b1534a7b7dfa1f311471d386d105"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_164_EXE {
    meta:
        original_name = "File164"
        file_type = "EXE"
        target_size = 12440
        target_md5 = "f3dec47bdc290fb01d5d908775321ea7"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_165_UNKNOWN {
    meta:
        original_name = "File165"
        file_type = "UNKNOWN"
        target_size = 696
        target_md5 = "1d786070021811ce3d962a420d868155"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0D 0A 2E 53 59 4E 4F 50 53 49 53 0D 0A 20 20 20 20 20 20 20 20 49 6E 73 74 61 6C 6C 73 20 43 68 6F 63 6F 6C 61 74 65 79 20 28 6E 65 65 }
    condition:
        $magic_bytes at 0
}

rule rule_166_EXE {
    meta:
        original_name = "File166"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "1af712a59ab34e0c131b40018d31c0f2"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_167_UNKNOWN {
    meta:
        original_name = "File167"
        file_type = "UNKNOWN"
        target_size = 1233
        target_md5 = "dfb1b490080d1aae0067e35550910c4d"
    strings:
        $magic_bytes = { 54 68 69 73 20 69 73 20 66 72 65 65 20 61 6E 64 20 75 6E 65 6E 63 75 6D 62 65 72 65 64 20 73 6F 66 74 77 61 72 65 20 72 65 6C 65 61 73 65 64 20 69 6E }
    condition:
        $magic_bytes at 0
}

rule rule_168_UNKNOWN {
    meta:
        original_name = "File168"
        file_type = "UNKNOWN"
        target_size = 7815
        target_md5 = "cc46e3e9ef97cbdc56318ee7ff23d73e"
    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4E 55 20 4C 45 53 53 45 52 20 47 45 4E 45 52 41 4C 20 50 55 42 4C 49 43 20 4C 49 43 45 4E }
    condition:
        $magic_bytes at 0
}

rule rule_169_UNKNOWN {
    meta:
        original_name = "File169"
        file_type = "UNKNOWN"
        target_size = 781
        target_md5 = "d44a541590b9d5973136d0e595da9ae2"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 35 31 32 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A }
    condition:
        $magic_bytes at 0
}

rule rule_170_DOCX {
    meta:
        original_name = "File170"
        file_type = "DOCX"
        target_size = 6138710
        target_md5 = "fb9de5ec633240495f1ee57735839420"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 C3 AA 5D 0E 8D 02 00 00 58 1D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_171_DOCX {
    meta:
        original_name = "File171"
        file_type = "DOCX"
        target_size = 1011368
        target_md5 = "19af6dc29171e27844e34c3c807231d9"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 33 A5 4B 35 8A 01 00 00 99 05 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_172_UNKNOWN {
    meta:
        original_name = "File172"
        file_type = "UNKNOWN"
        target_size = 17097
        target_md5 = "e322949af834af9a143a29625e33a4e4"
    strings:
        $magic_bytes = { 4D 6F 7A 69 6C 6C 61 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 56 65 72 73 69 6F 6E 20 32 2E 30 0D 0A 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D }
    condition:
        $magic_bytes at 0
}

rule rule_173_EXE {
    meta:
        original_name = "File173"
        file_type = "EXE"
        target_size = 19232
        target_md5 = "3c555bd977fd395f0e3e0b3758071d52"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_174_UNKNOWN {
    meta:
        original_name = "File174"
        file_type = "UNKNOWN"
        target_size = 113
        target_md5 = "a8dfc4d3598873ff3fd86e28be66108f"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 2F 61 20 61 3D 25 72 61 6E 64 6F 6D 25 20 25 25 20 31 30 30 0D 0A 73 65 74 20 2F 61 20 62 3D 25 72 61 6E }
    condition:
        $magic_bytes at 0
}

rule rule_175_UNKNOWN {
    meta:
        original_name = "File175"
        file_type = "UNKNOWN"
        target_size = 829
        target_md5 = "ec7522bc9873d8fb52d2dba4f19161ea"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 56 4C 43 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 69 73 20 50 }
    condition:
        $magic_bytes at 0
}

rule rule_176_EXE {
    meta:
        original_name = "File176"
        file_type = "EXE"
        target_size = 3072
        target_md5 = "6d8a087c87e8c522ae0b7948357ee226"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_177_EXE {
    meta:
        original_name = "File177"
        file_type = "EXE"
        target_size = 12064
        target_md5 = "894e538fbd29d9af2dac82abbb798aa8"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_178_UNKNOWN {
    meta:
        original_name = "File178"
        file_type = "UNKNOWN"
        target_size = 608
        target_md5 = "955ddefc4f016045fb167016e499dd15"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 4E 65 74 66 6C 69 78 0A 2E 44 45 53 43 52 49 50 54 49 4F 4E 0A 09 54 68 }
    condition:
        $magic_bytes at 0
}

rule rule_179_UNKNOWN {
    meta:
        original_name = "File179"
        file_type = "UNKNOWN"
        target_size = 9093
        target_md5 = "130668abb2367024e10447831c36f700"
    strings:
        $magic_bytes = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4C 69 63 65 6E 73 65 20 32 2E 30 0D 0A 0D 0A 09 20 20 20 20 43 6F 70 79 72 69 67 68 }
    condition:
        $magic_bytes at 0
}

rule rule_180_EXE {
    meta:
        original_name = "File180"
        file_type = "EXE"
        target_size = 2071847
        target_md5 = "6a9a905f16f64919e6892a2e8d37a5b7"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_181_DOCX {
    meta:
        original_name = "File181"
        file_type = "DOCX"
        target_size = 9567
        target_md5 = "cdc2e1b7b617de1db19b5820fc9380a0"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 00 08 08 00 42 3D 3C 5A 47 92 44 B2 5A 01 00 00 F0 04 00 00 13 00 04 00 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 53 }
    condition:
        $magic_bytes at 0
}

rule rule_182_PDF_1_4 {
    meta:
        original_name = "File182"
        file_type = "PDF-1.4"
        target_size = 490858
        target_md5 = "adc7a2cddbfa9080df9a9bce33153410"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 34 0D 25 E2 E3 CF D3 0D 0A 31 32 31 33 20 30 20 6F 62 6A 0D 3C 3C 2F 4C 69 6E 65 61 72 69 7A 65 64 20 31 2F 4C 20 34 39 30 38 36 }
    condition:
        $magic_bytes at 0
}

rule rule_183_DOCX {
    meta:
        original_name = "File183"
        file_type = "DOCX"
        target_size = 34148
        target_md5 = "5c4c9c4f71b373d50967fea0d9293b80"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 1C AD B2 D2 FA 01 00 00 6D 0B 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_184_PNG {
    meta:
        original_name = "File184"
        file_type = "PNG"
        target_size = 1660287
        target_md5 = "edf9fd64840aca234a2cf40acd08026d"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD F9 8F 24 5B 96 }
    condition:
        $magic_bytes at 0
}

rule rule_185_DOCX {
    meta:
        original_name = "File185"
        file_type = "DOCX"
        target_size = 870117
        target_md5 = "5b1392a9f190a431ac6bac3b2f5be47c"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 96 34 82 68 62 02 00 00 28 18 00 00 13 00 C5 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_186_UNKNOWN {
    meta:
        original_name = "File186"
        file_type = "UNKNOWN"
        target_size = 2176
        target_md5 = "cd58b4860366a300cfb76a652d6e1dbf"
    strings:
        $magic_bytes = { 4D 00 49 00 54 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 0D 00 0A 00 0D 00 0A 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 }
    condition:
        $magic_bytes at 0
}

rule rule_187_DOCX {
    meta:
        original_name = "File187"
        file_type = "DOCX"
        target_size = 23570
        target_md5 = "77d26a68e9264e9facac4242de2e740f"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 B5 F6 D3 96 8D 01 00 00 21 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_188_UNKNOWN {
    meta:
        original_name = "File188"
        file_type = "UNKNOWN"
        target_size = 10470
        target_md5 = "ce1742175ff199f4d207ac4edc013419"
    strings:
        $magic_bytes = { 4F 70 65 6E 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 28 22 4F 53 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 4F 70 65 6E 20 }
    condition:
        $magic_bytes at 0
}

rule rule_189_DOCX {
    meta:
        original_name = "File189"
        file_type = "DOCX"
        target_size = 95254
        target_md5 = "38c425bff814be81cacd15d2b4bcfeae"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 88 5E 62 0B CA 01 00 00 22 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_190_PNG {
    meta:
        original_name = "File190"
        file_type = "PNG"
        target_size = 1799942
        target_md5 = "2ebe5a3b54f71e08d247aaacd9536fc7"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD E9 B3 6D C7 75 }
    condition:
        $magic_bytes at 0
}

rule rule_191_DOCX {
    meta:
        original_name = "File191"
        file_type = "DOCX"
        target_size = 148835
        target_md5 = "7c3c2be5d0f5bd562546cc8d03829aa4"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 58 79 36 07 DF 01 00 00 23 0A 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_192_UNKNOWN {
    meta:
        original_name = "File192"
        file_type = "UNKNOWN"
        target_size = 319563
        target_md5 = "eb0293aa9d3cd061798d7fe931dc5fa6"
    strings:
        $magic_bytes = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_193_ZIP {
    meta:
        original_name = "File193"
        file_type = "ZIP"
        target_size = 466915
        target_md5 = "a7f70b3ec9911480be7dacbd1e37820d"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 00 00 00 00 21 00 FF FF FF FF 0C 02 00 00 0C 02 00 00 10 00 00 00 5B 74 72 61 73 68 5D 2F 30 30 30 30 2E 64 61 74 FF FF FF FF }
    condition:
        $magic_bytes at 0
}

rule rule_194_DOCX {
    meta:
        original_name = "File194"
        file_type = "DOCX"
        target_size = 1641870
        target_md5 = "44661e9d8e0b19cc4cdc71c58dac4595"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3E 11 88 CA 60 02 00 00 47 19 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_195_UNKNOWN {
    meta:
        original_name = "File195"
        file_type = "UNKNOWN"
        target_size = 87316
        target_md5 = "8581f7c7288375f14b8f164c83ea0ac9"
    strings:
        $magic_bytes = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 71 4B 4E 12 05 02 00 00 EC 0C 00 00 13 00 CD 01 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_196_DOCX {
    meta:
        original_name = "File196"
        file_type = "DOCX"
        target_size = 1379663
        target_md5 = "3acb832c0b5bcd7df8cc140a771c612e"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 62 EE 9D 68 5E 01 00 00 90 04 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_197_DOCX {
    meta:
        original_name = "File197"
        file_type = "DOCX"
        target_size = 2454899
        target_md5 = "abfdce4332a47d0056f54ecd5ff64e41"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 08 08 08 00 D2 41 75 59 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 77 6F 72 64 2F 68 65 61 64 65 72 31 2E 78 6D 6C A5 95 DB 8E }
    condition:
        $magic_bytes at 0
}

rule rule_198_ZIP {
    meta:
        original_name = "File198"
        file_type = "ZIP"
        target_size = 10412619
        target_md5 = "dd461e6bc31f224519587dffd93048f8"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 99 55 7E 05 F9 00 00 00 E1 02 00 00 0B 00 F3 01 5F 72 65 6C 73 2F 2E 72 65 6C 73 20 A2 EF 01 28 A0 00 02 00 }
    condition:
        $magic_bytes at 0
}

rule rule_199_PDF_1_7 {
    meta:
        original_name = "File199"
        file_type = "PDF-1.7"
        target_size = 266057
        target_md5 = "fd3900a6c106515c2db20b09720c7b3d"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 37 0D 0A 25 B5 B5 B5 B5 0D 0A 31 20 30 20 6F 62 6A 0D 0A 3C 3C 2F 54 79 70 65 2F 43 61 74 61 6C 6F 67 2F 50 61 67 65 73 20 32 20 }
    condition:
        $magic_bytes at 0
}

rule rule_200_EXE {
    meta:
        original_name = "File200"
        file_type = "EXE"
        target_size = 1543898
        target_md5 = "cb98f5f2982feefd5e6d9fca98bb7e39"
    strings:
        $magic_bytes = { 4D 5A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 B3 64 49 92 1E 88 7D AA 6A 76 }
    condition:
        $magic_bytes at 0
}

rule rule_201_EXE {
    meta:
        original_name = "File201"
        file_type = "EXE"
        target_size = 867014
        target_md5 = "4e9a6f255bff5ab93b6a7a51ebf62e99"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_202_UNKNOWN {
    meta:
        original_name = "File202"
        file_type = "UNKNOWN"
        target_size = 1204734
        target_md5 = "2497589c198a5c7d7c48f56bd5c2a083"
    strings:
        $magic_bytes = { 42 00 02 00 00 00 20 00 00 00 FF FF 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 FB 71 6A 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_203_UNKNOWN {
    meta:
        original_name = "File203"
        file_type = "UNKNOWN"
        target_size = 781
        target_md5 = "80d158a5fce462fb2d54c71adc8e0da6"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 50 72 69 6E 74 73 20 74 68 65 20 53 48 41 32 35 36 20 68 61 73 68 20 6F 66 20 61 20 66 69 6C 65 0A }
    condition:
        $magic_bytes at 0
}

rule rule_204_UNKNOWN {
    meta:
        original_name = "File204"
        file_type = "UNKNOWN"
        target_size = 681
        target_md5 = "d601a536054abe2a84612a08b5b749f5"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 4F 42 53 20 53 74 75 64 69 6F 20 28 6E 65 65 64 73 20 61 64 6D 69 6E 20 }
    condition:
        $magic_bytes at 0
}

rule rule_205_JPEG_JFIF {
    meta:
        original_name = "File205"
        file_type = "JPEG-JFIF"
        target_size = 169050
        target_md5 = "eae001e9a70c97bb5a2e6f17849c1d12"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_206_DOCX {
    meta:
        original_name = "File206"
        file_type = "DOCX"
        target_size = 209333
        target_md5 = "16aa2764840ee306b4d60ed118ed642b"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 24 EC 50 BF 82 01 00 00 24 07 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_207_EXE {
    meta:
        original_name = "File207"
        file_type = "EXE"
        target_size = 726251
        target_md5 = "8c5c9499e5bf2515b46ad201e8340748"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_208_DOCX {
    meta:
        original_name = "File208"
        file_type = "DOCX"
        target_size = 3060289
        target_md5 = "cb5e8db8123b89323a4822992b5ddd34"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 E4 A7 B0 6F EB 01 00 00 35 0D 00 00 13 00 08 02 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 }
    condition:
        $magic_bytes at 0
}

rule rule_209_PDF_1_3 {
    meta:
        original_name = "File209"
        file_type = "PDF-1.3"
        target_size = 202653
        target_md5 = "76909cea13b5097b22a7faa800652758"
    strings:
        $magic_bytes = { 25 50 44 46 2D 31 2E 33 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 54 79 70 65 20 2F 50 61 67 65 73 0A 2F 43 6F 75 6E 74 20 31 34 0A 2F }
    condition:
        $magic_bytes at 0
}

rule rule_210_ZIP {
    meta:
        original_name = "File210"
        file_type = "ZIP"
        target_size = 184563
        target_md5 = "d23ddb02acd5a876e306962bd71f1631"
    strings:
        $magic_bytes = { 50 4B 03 04 0A 00 00 00 08 00 00 00 21 00 FC 1F ED 11 25 02 00 00 43 05 00 00 10 00 00 00 64 6F 63 50 72 6F 70 73 2F 61 70 70 2E 78 6D 6C 9C 54 DF 6F }
    condition:
        $magic_bytes at 0
}

rule rule_211_XLSX {
    meta:
        original_name = "File211"
        file_type = "XLSX"
        target_size = 458026
        target_md5 = "c70ec8c66f59ecd212b7d08a4357b5d5"
    strings:
        $magic_bytes = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 3B F4 79 E3 2E 03 00 00 B8 10 00 00 14 00 00 00 78 6C 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C EC }
    condition:
        $magic_bytes at 0
}

rule rule_212_UNKNOWN {
    meta:
        original_name = "File212"
        file_type = "UNKNOWN"
        target_size = 182
        target_md5 = "4a08c4bd4d73b050f07c51d9d7192e57"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 61 64 76 69 63 65 3D 53 74 61 79 20 70 6F 73 69 74 69 76 65 2E 7C 54 61 6B 65 20 62 72 65 61 6B 73 2E 7C }
    condition:
        $magic_bytes at 0
}

rule rule_213_EXE {
    meta:
        original_name = "File213"
        file_type = "EXE"
        target_size = 66043
        target_md5 = "2a951f81a38691f52fb9985513e46946"
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $magic_bytes at 0
}

rule rule_214_JPEG_JFIF {
    meta:
        original_name = "File214"
        file_type = "JPEG-JFIF"
        target_size = 166868
        target_md5 = "3938baaa0bb6e35e2420178db164cb3d"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_215_UNKNOWN {
    meta:
        original_name = "File215"
        file_type = "UNKNOWN"
        target_size = 643
        target_md5 = "ebc84c0bae4a06d2db24c264d52dbb1f"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 43 6F 64 65 0A 2E 44 45 53 43 }
    condition:
        $magic_bytes at 0
}

rule rule_216_UNKNOWN {
    meta:
        original_name = "File216"
        file_type = "UNKNOWN"
        target_size = 628
        target_md5 = "825341f997632ff776e477883fe6493c"
    strings:
        $magic_bytes = { EF BB BF 3C 23 0A 2E 53 59 4E 4F 50 53 49 53 0A 09 49 6E 73 74 61 6C 6C 73 20 47 69 74 20 45 78 74 65 6E 73 69 6F 6E 73 0A 2E 44 45 53 43 52 49 50 54 }
    condition:
        $magic_bytes at 0
}

rule rule_217_UNKNOWN {
    meta:
        original_name = "File217"
        file_type = "UNKNOWN"
        target_size = 14118
        target_md5 = "f1e7f2ec19d0fd37d892e992a71fcbd6"
    strings:
        $magic_bytes = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 45 55 52 4F 50 45 41 4E 20 55 4E 49 4F 4E 20 50 55 42 4C 49 43 20 4C 49 43 45 4E 43 }
    condition:
        $magic_bytes at 0
}

rule rule_218_PNG {
    meta:
        original_name = "File218"
        file_type = "PNG"
        target_size = 1394042
        target_md5 = "bb84661af617931ba5b294a8737c421d"
    strings:
        $magic_bytes = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 69 B0 6D C9 75 }
    condition:
        $magic_bytes at 0
}

rule rule_219_JPEG_JFIF {
    meta:
        original_name = "File219"
        file_type = "JPEG-JFIF"
        target_size = 127189
        target_md5 = "e87decf883153221f84d73f70bb2f53b"
    strings:
        $magic_bytes = { FF D8 FF E0 00 10 45 58 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    condition:
        $magic_bytes at 0
}

rule rule_220_UNKNOWN {
    meta:
        original_name = "File220"
        file_type = "UNKNOWN"
        target_size = 191
        target_md5 = "db631805541e0958fd9e6e3616a42c98"
    strings:
        $magic_bytes = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 77 6F 72 64 3D 68 65 6C 6C 6F 0D 0A 73 65 74 20 73 63 72 61 6D 62 6C 65 64 3D 0D 0A 66 6F 72 20 2F 6C 20 }
    condition:
        $magic_bytes at 0
}