rule Suspicious_SFX
{
	meta:
		description = "Detects self-extracting archives (SFX) executing cmd.exe or powershell.exe"
		author = "marcin@ulikowski.pl"
		date = "2023-04-04"
		reference = "https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/"

	strings:
		$rar = { 52 61 72 21 }
		$zip = { 50 4b 03 04 }
		$setup_cmd = "\nSetup=cmd"
		$setup_powershell = "\nSetup=powershell"
		$silent = "\nSilent=1"

	condition:
		filesize < 1MB
		and uint16be(0) == 0x4d5a
		and any of ($zip, $rar)
		and any of ($setup_*)
		and $silent
}
