
rule Trojan_BAT_Bladabindi_AAME_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AAME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 07 16 11 06 1f 0f 1f 10 28 90 01 01 00 00 0a 00 06 11 06 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 13 05 02 28 90 01 01 00 00 0a 13 04 28 90 01 01 00 00 0a 11 05 11 04 16 11 04 8e b7 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b de 10 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}