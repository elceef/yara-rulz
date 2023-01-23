rule PE32_OneNote
{
	meta:
		description = "Detects FileDataStoreObject structure with PE32 in OneNote files"
		author = "marcin@ulikowski.pl"
		date = "2023-01-22"
		hash1 = "f408ef3fa89546483ba63f58be3f27a98795655eb4b9b6217cbe302a5ba9d5f7"

	strings:
		$magic = { ae b1 53 78 d0 29 96 d3 }
		$fdso_pe32 = { a4 c4 8d 4d 0b 7a 9e ac [20] 4d 5a }

	condition:
		$magic at 8 and $fdso_pe32
}
