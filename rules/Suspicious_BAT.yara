rule BAT_Obfuscated_SetEnv
{
	meta:
		description = "Detects batch script with obfuscated SET command located directly after @echo off"
		author = "marcin@ulikowski.pl"
		date = "2023-05-01"
		modified = "2023-05-05"
		hash1 = "a0f43c5748ada07a12af81dda2460045030f936a8d5081f3a403f85c2a9668f8"
		hash2 = "1a0ca873412474a6437d33e48071aa0169f8317b5c996e1b10a41791707b2cf5"
		hash3 = "83e47d4f3dd43ed01dc573f0b83e9e71f0ec75b6ea5712f640585d01d8aedf3c"
		hash4 = "cf351a2b1f0a157a92be2e01e460140e2c1d0ee1685474144f2203a97d2de489"
		reference = "https://twitter.com/wdormann/status/1651631372438585344"

	strings:
		$s1 = { 40 65 63 68 6f 20 6f 66 66 0d 0a ( 73 65 25 | 73 25 | 25 ) [2-26] 3a 7e [0-6] 3? 25 ( 25 | 20 | 65 25 | 74 20 | 65 74 20 ) }
		$s2 = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 22 [4] 3d 73 65 74 20 22 0d 0a 25 }

	condition:
		$s1 in (0..4) or $s2 in (0..4)
}

rule BAT_Chunked_Payload_SetEnv
{
	meta:
		description = "Detects batch script storing chunks of payload in random environment variables"
		author = "marcin@ulikowski.pl"
		date = "2023-05-05"
		hash1 = "f73521adbf89be99c4d7ea74ebf7fed815af49ce4dc060656d7c9c631e4d0538"

	strings:
		$echo = "@echo off"
		$set = { ( 0d 0a | 26 20 ) 73 65 74 20 22 [10] 3d [2-6] 22 }

	condition:
		$echo in (0..4) and
		#set > 10
}
