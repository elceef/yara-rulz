rule Base64_SVG_Javascript
{
	meta:
		description = "Detects base64 encoded SVG objects containing Javascript"
		author = "marcin@ulikowski.pl"
		date = "2022-10-25"
		hash1 = "fe394a59e961c3fbcc326e7d0ee5909596de55249e669bc4da0aed172c11fda8"
		hash2 = "f0c94f2705b1aea17f4a6c6d71c6ed725fe71bf66b03b0117060010859ca8a19"

	strings:
		$svg = "\"data:image/svg+xml;base64" wide ascii
		$js = "<script type=\"text/javascript\">" base64 // YARA >= 4.0.0

	condition:
		all of them
}
