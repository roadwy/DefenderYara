
rule Trojan_BAT_Bladabindi_NZC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 06 95 06 11 06 1f 0f 5f 95 61 13 07 06 11 06 1f 0f 5f 06 } //01 00 
		$a_01_1 = {20 de a8 01 00 26 20 de a8 01 00 8d 18 00 00 01 25 d0 02 00 00 04 } //01 00 
		$a_01_2 = {35 38 35 2d 38 66 30 33 2d 33 33 32 63 35 62 35 64 62 34 31 66 } //00 00 
	condition:
		any of ($a_*)
 
}