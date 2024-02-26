
rule Trojan_BAT_Bladabindi_SPDU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SPDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 0b 7e 0e 00 00 04 6f 90 01 03 0a 6f 90 01 03 0a 2c 2d 28 90 01 03 06 13 07 06 11 07 16 28 90 01 03 0a 16 2e 1a 11 07 0a 72 8d 05 00 70 7e 21 00 00 04 11 07 28 90 01 03 0a 28 90 01 03 06 26 de 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}