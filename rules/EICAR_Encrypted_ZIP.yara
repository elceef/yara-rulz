/*
	This is proof of concept YARA rule demonstrating that any known file
	(with known checksum and size) can be detected in any encrypted ZIP archive
	without the need for the password.
	The rule takes advantage of the fact that the ZIP format requires CRC-32
	checksum and uncompressed size for the original file.
	
	$ crc32 eicar.com.txt
	6851cf3c
	$ wc -c eicar.com.txt
	68 eicar.com.txt
*/

rule EICAR_Encrypted_ZIP
{
	meta:
		description = "Detects EICAR file in any encrypted ZIP archive"
		author = "marcin@ulikowski.pl"
		date = "2022-12-13"

	strings:
		$local = {
			50 4b 03 04 // local file header signature (PK)
			?? 00 // minimum version
			?? 00 // flags (bit 0 and 6 indicate encryption)
			?? 00 // compression method
			?? ?? // last modification time
			?? ?? // last modification date
			?? ?? ?? ?? // CRC-32 of uncompressed and unencrypted data
			?? ?? ?? ?? // compressed size
			?? ?? ?? ?? // uncompressed size
			}

	condition:
		// for any ZIP local file header:
		for any i in (1..#local) : (
			// encryption flag set
			(uint8(@local[i] + 6) & 0x01 or uint8(@local[i] + 6) & 0x40) and
			// CRC-32
			uint32(@local[i] + 14) == 0x6851cf3c and
			// uncompressed size
			uint32(@local[i] + 22) == 68
			)
}
