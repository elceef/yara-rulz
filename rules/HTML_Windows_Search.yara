rule HTML_Windows_Search_Abuse
{
	meta:
		description = "Detects HTML files abusing Windows system functionalities to redirect and download malicious payloads"
		author = "marcin@ulikowski.pl"
		date = "2024-06-15"
		hash1 = "d136dcfc355885c502ff2c3be229791538541b748b6c07df3ced95f9a7eb2f30"

	strings:
		$location1 = "location.href" wide ascii
		$location2 = "location.replace(" wide ascii
		$location3 = "location.assign(" wide ascii
		$metarefresh = "<meta http-equiv=\"refresh\"" nocase wide ascii
		$search1 = "\"search-ms:query=" wide ascii
		$search2 = "\"search:query=" wide ascii
		$search3 = "URL=search:query=" wide ascii
		$crumb1 = "&crumb=location:" wide ascii
		$crumb2 = "&amp;crumb=location:" wide ascii

	condition:
		(any of ($location*) or $metarefresh) and any of ($search*) and any of ($crumb*)
}
