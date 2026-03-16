/*
    Evasion/smuggling technique mislabeling compressed payload as uncompressed
	data within ZIP headers. While effective at hiding, it requires a custom
	loader because standard extraction tools flag the malformed archive as
	corrupt.

	This technique is tracked as CVE-2026-0866, even though it isn't technically
	a vulnerability.
*/

rule Zombie_Malformed_ZIP
{
	meta:
		description = "Malformed ZIP with header declaring method STORED while having DEFLATE-compressed payload"
		author = "marcin@ulikowski.pl"
		date = "2026-03-15"
		hash1 = "7316a4c3cd1cf183925ab4b7e77dbf52b38180ee1faf0156d7ea410f42cb5e76"
		reference = "https://github.com/bombadil-systems/zombie-zip"

	strings:
		$local = {
			50 4b 03 04 // LFH signature
			?? 00 // minimum version
			?? 00 // flags
			00 00 // compression method = STORED (no compression)
			?? ?? // last modification time
			?? ?? // last modification date
			?? ?? ?? ?? // CRC-32
			?? ?? ?? ?? // compressed size
			?? ?? ?? ?? // uncompressed size
			}

	condition:
		// for any LFH:
		for any i in (1..#local) : (
			// different compressed and uncompressed size
			uint32(@local[i] + 18) != uint32(@local[i] + 22)
			)
}
