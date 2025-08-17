rule WinRAR_CVE_2025_8088_Exploit
{
	meta:
		description = "Detects RAR archives exploiting CVE-2025-8088 in WinRAR"
		author = "marcin@ulikowski.pl"
		date = "2025-08-18"
		modified = "2025-08-18"
		hash1 = "2a8fafa01f6d3863c87f20905736ebab28d6a5753ab708760c0b6cf3970828c3"
		reference = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"

	strings:
		// service header for NTFS ADS with path traversal
		$ = { 00 03 53 54 4d [2-3] 3a ( 5c | 2e ) ( 5c | 2e ) ( 5c | 2e ) ( 5c | 2e ) }

	condition:
		uint32be(0) == 0x52617221 and all of them
}
