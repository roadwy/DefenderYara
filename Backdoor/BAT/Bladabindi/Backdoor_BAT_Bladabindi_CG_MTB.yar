
rule Backdoor_BAT_Bladabindi_CG_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 0e 11 0f 9a 13 05 09 11 05 6f 90 01 03 0a 74 90 01 03 1b 13 06 12 04 11 04 8e 69 11 06 8e 69 58 28 90 00 } //01 00 
		$a_03_1 = {11 06 16 11 04 11 04 8e 69 11 06 8e 69 59 11 06 8e 69 28 90 01 03 0a 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 90 00 } //02 00 
		$a_01_2 = {41 41 68 76 55 45 34 72 45 51 54 64 49 61 6f 51 35 6a 53 } //00 00 
	condition:
		any of ($a_*)
 
}