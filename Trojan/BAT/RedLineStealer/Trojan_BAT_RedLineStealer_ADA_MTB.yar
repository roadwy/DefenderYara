
rule Trojan_BAT_RedLineStealer_ADA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 2d 17 26 7e 90 01 02 00 04 fe 06 90 01 02 00 06 73 90 01 02 00 0a 25 80 90 01 02 00 04 28 90 01 02 00 0a 74 90 01 02 00 01 28 90 01 02 00 0a 72 90 01 02 00 70 28 90 01 02 00 06 de 03 26 de 00 2a 90 00 } //01 00 
		$a_03_1 = {06 25 02 7d 90 01 02 00 04 fe 06 90 01 02 00 06 73 90 01 02 00 0a 16 8d 90 01 02 00 01 28 90 01 02 00 2b 2c 06 73 90 01 02 00 0a 7a 90 00 } //01 00 
		$a_03_2 = {12 00 fe 15 02 00 00 1b 02 6f 90 01 02 00 0a 0a de 03 26 de 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}