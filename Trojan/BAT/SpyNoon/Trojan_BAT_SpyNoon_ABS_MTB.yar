
rule Trojan_BAT_SpyNoon_ABS_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 28 0a 00 00 0a 0a 06 18 6f 0b 00 00 0a 00 06 18 6f 0c 00 00 0a 00 06 72 01 00 00 70 28 0d 00 00 0a 6f 0e 00 00 0a 00 06 6f 0f 00 00 0a 02 16 02 8e 69 6f 10 00 00 0a 0b 2b 00 07 2a } //02 00 
		$a_01_1 = {00 28 11 00 00 0a 02 28 0d 00 00 0a 28 01 00 00 06 6f 12 00 00 0a 0a 2b 00 06 2a } //02 00 
		$a_01_2 = {48 74 6d 6c 44 65 63 6f 64 65 } //02 00  HtmlDecode
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //02 00  FromBase64String
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00  DownloadString
	condition:
		any of ($a_*)
 
}