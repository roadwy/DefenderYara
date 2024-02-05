
rule Trojan_BAT_Heracles_AHL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 4e 00 00 01 28 90 01 03 06 74 01 00 00 1b 28 90 01 03 06 17 2d 03 26 de 06 0a 2b fb 26 de d0 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_AHL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 90 01 03 06 1b 2d 1c 26 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //00 00 
	condition:
		any of ($a_*)
 
}