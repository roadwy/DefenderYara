
rule Trojan_BAT_DarkTortilla_NEAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0b 07 8e 69 17 d6 8d 43 00 00 01 0a 06 8e 69 17 da 0c 16 0d 2b 0f 06 09 07 16 9a 6f 88 00 00 0a a2 09 17 d6 0d 09 08 31 ed } //0a 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 74 00 65 00 78 00 74 00 62 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 72 00 61 00 77 00 2f 00 76 00 77 00 61 00 65 00 75 00 77 00 70 00 6f 00 6e 00 70 00 } //02 00  https://textbin.net/raw/vwaeuwponp
		$a_01_2 = {41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 } //02 00  AppleWebKit/537.36
		$a_01_3 = {4c 00 6f 00 61 00 64 00 } //00 00  Load
	condition:
		any of ($a_*)
 
}