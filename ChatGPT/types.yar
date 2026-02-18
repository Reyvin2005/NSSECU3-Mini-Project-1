// this contains the updated rule set

// rule #1
rule PDF
{
    meta:
        description = "Detects PDF files of any version using magic bytes only"
        category = "Document"
        method = "Magic byte detection"

    strings:
        $pdf = { 25 50 44 46 2D ?? 2E ?? }

    condition:
        $pdf at 0
}

// rule #2
rule PNG {
    meta:
        description = "Detects PNG File"
        category = "Image"

    strings:
        $magic = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        $magic at 0
}

// rule #3
rule JPEG
{
    meta:
        description = "Detects JPEG images (generalized)"
        category = "Image"

    strings:
        $header = { FF D8 FF }

    condition:
        $header in (0..20)
}

// rule #4
rule ZIP
{
    meta:
        description = "Detects ZIP archives (PKZIP format)"
        category = "Archive"

    strings:
        $zip1 = { 50 4B 03 04 }
        $zip2 = { 50 4B 05 06 }
        $zip3 = { 50 4B 07 08 }

    condition:
        any of them at 0
}

// rule #5
rule MP3
{
    meta:
        description = "Detects MP3 audio files"
        category = "Multimedia"

    strings:
        $id3 = { 49 44 33 }
        $mpeg1 = { FF FB }
        $mpeg2 = { FF F3 }
        $mpeg3 = { FF F2 }

    condition:
        $id3 at 0 or
        $mpeg1 at 0 or
        $mpeg2 at 0 or
        $mpeg3 at 0
}

// rule #6
rule EXE
{
    meta:
        description = "Basic Windows executable detection"
        category = "Executable"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}

// rule #7
rule RIFF
{
    meta:
        description = "Detects RIFF container format"
        category = "Multimedia"

    strings:
        $riff = { 52 49 46 46 }

    condition:
        $riff at 0
}

// rule #8
rule PS_I_UTF8
{
    meta:
        description = "UTF-8 PowerShell installer scripts"

    strings:
        $bom = { EF BB BF }
        $comment = "<#"
        $synopsis = ".SYNOPSIS"

    condition:
        $bom at 0 and
        $comment in (0..20) and
        $synopsis in (0..200)
}

// rule #9
rule BAT
{
    meta:
        description = "Windows Batch script file"
        category = "Script"

    strings:
        $bat = { 40 65 63 68 6F 20 6F 66 66 }  // "@echo off"

    condition:
        $bat at 0
}

// rule #10
rule CD00
{
    meta:
        description = "CD00 structured binary variant"

    strings:
        $cd = { 43 44 30 30 14 00 06 00 08 }

    condition:
        $cd at 0
}

// rule #11
rule TXT_ASCII
{
    condition:
        filesize < 5MB and
        for all i in (0..filesize-1):
            (uint8(i) == 0x09 or
             uint8(i) == 0x0A or
             uint8(i) == 0x0D or
             (uint8(i) >= 0x20 and uint8(i) <= 0x7E))
}

// rule #12
rule TXT_UTF16
{
    meta:
        description = "UTF-16 LE encoded text file"
        category = "Text"

    condition:
        uint8(1) == 0x00 and
        uint8(3) == 0x00
}

// rule #13
rule ISO
{
    meta:
        description = "ISO 9660 image (CD001 variant)"
        category = "Archive"

    strings:
        $iso = { 43 44 30 30 31 }

    condition:
        $iso at 0
}






