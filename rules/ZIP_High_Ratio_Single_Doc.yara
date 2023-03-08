/*
	This signature detects ZIP archives with the following conditions:
	- contains single file with .doc extension
	- uncompressed size > 100MB
	- compressed size < 1MB
*/

rule ZIP_High_Ratio_Single_Doc
{
	meta:
		description = "Detects ZIP archives containing single MS Word document with unusually high compression ratio"
		author = "marcin@ulikowski.pl"
		date = "2023-03-08"
		hash1 = "4d9a6dfca804989d40eeca9bb2d90ef33f3980eb07ca89bbba06d0ef4b37634b"
		hash2 = "4bc2d14585c197ad3aa5836b3f7d9d784d7afe79856e0ddf850fc3c676b6ecb1"

	strings:
		$magic = { 50 4b 03 04 }
		$ext = ".doc"

	condition:
		filesize < 1MB and
		$magic at 0 and
		#magic == 1 and
		uint32(22) > 1024*1024*100 and
		$ext at (uint16(26) + 26)
}
