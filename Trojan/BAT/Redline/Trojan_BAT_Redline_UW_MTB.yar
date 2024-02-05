
rule Trojan_BAT_Redline_UW_MTB{
	meta:
		description = "Trojan:BAT/Redline.UW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 05 19 8d 90 01 03 01 13 13 11 13 16 28 90 01 03 0a 6f 90 01 03 0a a2 11 13 17 7e 90 01 03 0a a2 11 13 18 09 11 05 6f 90 01 03 0a a2 11 13 13 06 72 90 01 03 70 28 90 01 03 06 28 90 01 03 06 13 07 28 90 01 03 0a 11 07 6f 90 01 03 0a 13 08 72 90 01 03 70 13 09 11 09 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}