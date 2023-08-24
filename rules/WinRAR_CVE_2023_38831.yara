rule WinRAR_CVE_2023_38831_Exploit
{
	meta:
		description = "Detects ZIP archives exploiting CVE-2023-38831 in WinRAR"
		author = "marcin@ulikowski.pl"
		date = "2023-09-23"
		hash1 = "00175d538cba0c493e397a0b7f4b28f9a90dd0ee40f69795ae28d23ce0d826c0"
		reference = "https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day"

	strings:
		$ = { 50 4b 03 04 [24] 00 00 [3-64] 2e ?? ?? ?? 20 2f [3-64] 2e ?? ?? ?? 20 2e ( 626174 | 636d64 | 707331 ) ( 2e20 | 20 ) }

	condition:
		uint16be(0) == 0x504b and all of them
}  
