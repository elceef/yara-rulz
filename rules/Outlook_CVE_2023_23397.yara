rule Outlook_CVE_2023_23397_Exploit
{
	meta:
		description = "Detects Outlook meeting/appointment/task files with ReminderSoundFile property set to UNC path"
		author = "marcin@ulikowski.pl"
		date = "2023-03-16"
		hash1 = "52dbaf64ce1a5cd1db9a9d385f8204e5f665ca53a3d904033bf1a10369490646"
		hash2 = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"

	strings:
		$magic = { d0 cf 11 e0 }
		$pid_reminder_file = { 1f 85 00 00 }
		$psetid_appointment = { 02 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 da d8 6e 0b 45 1b 10 98 da 00 aa 00 3f 13 05 }
		$unc_ascii = {
			00 5c 5c
			(31|32|33|34|35|36|37|38|39)
			(30|31|32|33|34|35|36|37|38|39|2e)
			(30|31|32|33|34|35|36|37|38|39|2e)
			(30|31|32|33|34|35|36|37|38|39|2e)
			}
		$unc_unicode = {
			00 00 5c 00 5c 00
			(31|32|33|34|35|36|37|38|39) 00
			(30|31|32|33|34|35|36|37|38|39|2e) 00
			(30|31|32|33|34|35|36|37|38|39|2e) 00
			(30|31|32|33|34|35|36|37|38|39|2e) 00
			}

	condition:
		filesize < 1MB and
		$magic at 0 and
		$pid_reminder_file and
		1 of ($psetid_*) and
		1 of ($unc_*)
}
