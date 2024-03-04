rule Obfuscated_IP_Address_in_URL
{
	meta:
		description = "Detects hexadecimal and octal IP address representations in URL"
		author = "marcin@ulikowski.pl"
		date = "2020-09-17"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/evasive-urls-in-spam/"

	strings:
		$ = /="?http:\/\/0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.?\// nocase ascii wide
		$ = /="?http:\/\/0x[0-9a-f]{8}\.?\// nocase ascii wide
		$ = /="?http:\/\/0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.?\// nocase ascii wide
		$ = /="?http:\/\/[0-9]{8,10}\.?\// nocase ascii wide

	condition:
		any of them
}
