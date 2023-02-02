rule HTA_WScriptShell_OneNote
{
	meta:
		description = "Detects suspicious OneNote documents with embedded HTA + WScript.Shell"
		author = "marcin@ulikowski.pl"
		date = "2023-02-01"
		hash1 = "002fe00bc429877ee2a786a1d40b80250fd66e341729c5718fc66f759387c88c"

	strings:
		$magic = { ae b1 53 78 d0 29 96 d3 }
		$hta = { 00 04 00 00 00 2e 00 68 00 74 00 61 }
		$wsh = "CreateObject(\"WScript.Shell\")"

	condition:
		filesize < 5MB and
		$magic at 8 and $wsh and $hta
}
