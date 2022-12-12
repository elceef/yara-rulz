rule OLE2_AutoOpen_Reversed_Payload
{
	meta:
		description = "Detects suspiciously reversed payloads in OLE2 objects with auto-open macros"
		author = "marcin@ulikowski.pl"
		date = "2021-12-01"

	strings:
		$magic = { d0 cf 11 e0 a1 b1 1a e1 }
		$auto_open = /(auto|document|workbook)_?(open|close)/ wide ascii nocase
		$http = /\/\/:s?ptth/ wide ascii
		$programdata = /\\ataDmargorP\\\\?:C/ wide ascii nocase
		$windows = /\\swodniW\\\\?:C/ wide ascii nocase

	condition:
		filesize < 1MB
		and $magic at 0
		and $auto_open
		and any of ($http, $programdata, $windows)
}
