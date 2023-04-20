rule Outlook_CVE_2023_23397_Exploit
{
	meta:
		description = "Detects Outlook meeting/appointment/task files with ReminderSoundFile property set to UNC path"
		author = "marcin@ulikowski.pl"
		date = "2023-03-16"
		modified = "2023-04-20"
		hash1 = "52dbaf64ce1a5cd1db9a9d385f8204e5f665ca53a3d904033bf1a10369490646"
		hash2 = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash3 = "078b5023cae7bd784a84ec4ee8df305ee7825025265bf2ddc1f5238c3e432f5f"
		hash4 = "1867bc9f81e99a55103288ce10c5c05267119ebb13757686e59bfed156f62b51"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"

	strings:
		$pid_reminder_file = { 1f 85 00 00 0? 00 ?? 00 }
		$pid_reminder_override = { 1c 85 00 00 0? 00 ?? 00 }
		$psetid_common = { 08 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$psetid_appointment = { 02 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$unc = /\\\\[a-z1-9][a-z0-9.]{6}/ wide ascii

	condition:
		filesize < 1MB and
		(uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x789f3e22) and
		($psetid_appointment or $psetid_task) and
		$psetid_common and
		($pid_reminder_file and $pid_reminder_override) and
		$unc
}
