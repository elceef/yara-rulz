rule HTML_Smuggling_A
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		date = "2021-05-13"
		modified = "2023-04-16"
		hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"

	strings:
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$element = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 ( 28 | 22 | 27 ) }
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$download = { ( 2e | 22 | 27 ) 64 6f 77 6e 6c 6f 61 64 ( 3d | 22 | 27 ) }
		$click = { ( 2e | 22 | 27 ) 63 6c 69 63 6b ( 3d | 22 | 27 ) }
		$atob = { 61 74 6f 62 ( 28 | 22 | 27 ) }
		$blob = "new Blob("
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize < 5MB
		and ($mssave or (#element == 1 and #objecturl == 1 and #download == 1 and #click == 1))
		and $blob and $array and $atob
		and (#ole2 + #pe32 + #iso + #udf + #zip + #jsxor) == 1
}

rule HTML_Smuggling_B
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		date = "2022-12-02"
		modified = "2023-04-16"
		hash1 = "63955db0ccd6c0613912afb862635bde0fa925847f27adc8a0d65c994a7e05ea"

	strings:
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$atob = "atob("
		$blob = "new Blob("
		$file = "new File(["
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize < 5MB
		and $atob
		and #objecturl == 1 and #file == 1 and #blob == 1 and #array == 1
		and (#ole2 + #pe32 + #iso + #udf + #zip + #jsxor) == 1
}

rule HTML_Smuggling_C
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		date = "2023-04-17"
		hash1 = "0b4cdfc8ae8ae17d7b6786050f1962c19858b91febb18f61f553083f57d96fea"
		hash2 = "2b99bf97f3d02ba3b44406cedd1ab31824723b56a8aae8057256cc87870c199e"
		hash3 = "904ea1ada62cfd4b964a6a3eb9bab5b98022ab000f77b75eb265a2ac44b45b37"

	strings:
		$blob = "new Blob("
		$array = "new Uint8Array("
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$loop = { ?? 5b 69 5d ( 3d | 20 3d | 3d 20 | 20 3d 20 ) ?? 5b 69 5d ( 2d | 20 2d | 2d 20 | 20 2d 20 ) 3? 3b }

	condition:
		filesize < 5MB
		and $mssave
		and #blob == 1 and #array == 1 and #loop == 1
}
