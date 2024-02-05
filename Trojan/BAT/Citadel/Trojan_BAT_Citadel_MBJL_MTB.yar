
rule Trojan_BAT_Citadel_MBJL_MTB{
	meta:
		description = "Trojan:BAT/Citadel.MBJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 11 05 91 0b 02 11 05 17 d6 91 0d 18 09 d8 03 da 07 da 13 04 03 07 da 09 d6 0c 2b 08 08 20 00 01 00 00 d6 0c 08 16 32 f4 } //01 00 
		$a_01_1 = {39 2d 35 66 65 61 66 38 34 62 66 31 37 62 } //00 00 
	condition:
		any of ($a_*)
 
}