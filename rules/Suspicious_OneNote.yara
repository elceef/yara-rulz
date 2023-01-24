rule Suspicious_OneNote
{
	meta:
		description = "Detects OneNote documents with FileDataStoreObject structure containing PE32 or batch script"
		author = "marcin@ulikowski.pl"
		date = "2023-01-22"
		hash1 = "f408ef3fa89546483ba63f58be3f27a98795655eb4b9b6217cbe302a5ba9d5f7"
		hash2 = "5306fa7940b4d67dfb031fd315b661cecb2ce81e2f34c9393e1826df0f0bbdc5"

	strings:
		$magic = { ae b1 53 78 d0 29 96 d3 }
		$fdso_pe32 = { a4 c4 8d 4d 0b 7a 9e ac [20] 4d 5a }
		$fdso_bat = { a4 c4 8d 4d 0b 7a 9e ac [20] 40 65 63 68 6f 20 6f 66 66 } // @echo off

	condition:
		$magic at 8 and ($fdso_pe32 or $fdso_bat)
}
