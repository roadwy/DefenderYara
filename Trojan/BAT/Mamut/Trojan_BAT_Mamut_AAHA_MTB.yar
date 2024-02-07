
rule Trojan_BAT_Mamut_AAHA_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AAHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {04 07 08 16 6f 90 01 01 00 00 0a 13 05 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 06 3a 90 01 01 00 00 00 26 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}