rule HTML_Smuggling_A
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		date = "2021-05-13"
		hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"

	strings:
		$mssave = /[."']msSave/ wide ascii
		$element = /[."']createElement[("']/ wide ascii
		$objecturl = /[."']createObjectURL[("']/ wide ascii
		$download = /[."']download[="']/ wide ascii
		$click = /[."']click[("']/ wide ascii
		$atob = /atob[("']/ wide ascii
		$blob = "new Blob(" wide ascii
		$array = "new Uint8Array(" wide ascii
		$ole2 = "0M8R4KGxGuEA" wide ascii
		$pe32 = "TVqQAAMAAAAE" wide ascii
		$iso = "AAAABQ0QwMDE" wide ascii
		$udf = "AAAAQkVBMDEB" wide ascii
		$zip = /UEsDB[ABCD][o0MQ][AD][AC]/ wide ascii
		$jsxor = /\.charCodeAt\(.{1,10}\) ?\^/ wide ascii

	condition:
		filesize < 5MB
		and ($mssave or (#element == 1 and #objecturl == 1 and #download == 1 and #click == 1))
		and $blob and $array and $atob and (#ole2 + #pe32 + #iso + #udf + #zip + #jsxor) == 1
}

rule HTML_Smuggling_B
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		date = "2022-12-02"
		hash1 = "63955db0ccd6c0613912afb862635bde0fa925847f27adc8a0d65c994a7e05ea"

	strings:
		$objecturl = /[."']createObjectURL[("']/ wide ascii
		$atob = "atob(" wide ascii
		$blob = "new Blob(" wide ascii
		$file = "new File([" wide ascii
		$array = "new Uint8Array(" wide ascii
		$ole2 = "0M8R4KGxGuEA" wide ascii
		$pe32 = "TVqQAAMAAAAE" wide ascii
		$iso = "AAAABQ0QwMDE" wide ascii
		$udf = "AAAAQkVBMDEB" wide ascii
		$zip = /UEsDB[ABCD][o0MQ][AD][AC]/ wide ascii
		$jsxor = /\.charCodeAt\(.{1,10}\) ?\^/ wide ascii

	condition:
		filesize < 5MB
		and #objecturl == 1 and #file == 1 and #blob == 1 and #array == 1 and #atob > 0
		and (#ole2 + #pe32 + #iso + #udf + #zip + #jsxor) == 1
}
