
rule Backdoor_BAT_Bladabindi_KAI_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 08 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 0e 06 5a 11 06 58 20 07 88 d4 e0 20 f9 78 2b 1f 58 5e d2 61 d2 81 90 01 01 00 00 01 11 0e 06 5a 11 05 58 20 f0 1e e0 04 20 fc fe 4c 5f 58 20 ec 1d 2c 64 59 5e d1 0a 11 0e 11 06 5a 11 0c 58 20 9f 2f f5 d1 20 61 d0 0b 2e 58 5e d1 13 06 11 08 17 58 13 08 11 08 11 04 8e 69 fe 04 2d 94 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}