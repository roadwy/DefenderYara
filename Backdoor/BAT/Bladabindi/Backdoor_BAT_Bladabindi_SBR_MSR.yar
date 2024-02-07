
rule Backdoor_BAT_Bladabindi_SBR_MSR{
	meta:
		description = "Backdoor:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 26 28 90 02 02 00 06 28 08 00 00 0a 72 90 02 02 00 70 28 90 02 02 00 06 28 08 00 00 0a 28 10 00 00 0a 2a 90 00 } //01 00 
		$a_03_1 = {0a 06 26 28 90 02 02 00 06 28 07 00 00 0a 0b 28 90 02 02 00 06 28 08 00 00 0a 0c 18 0d 18 8d 01 00 00 01 13 04 11 04 16 28 90 02 02 00 06 a2 07 08 09 11 04 28 09 00 00 0a 2a 90 00 } //01 00 
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //00 00  GetDomain
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Bladabindi_SBR_MSR_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 0b 00 00 04 28 20 00 00 0a 72 90 01 01 00 00 70 7e 0a 00 00 04 28 21 00 00 0a 0b 28 04 00 00 06 6f 22 00 00 0a 07 6f 23 00 00 0a 90 00 } //01 00 
		$a_03_1 = {20 d0 07 00 00 28 2f 00 00 0a 1f 1c 28 5a 00 00 0a 72 90 01 01 03 00 70 28 1e 00 00 0a 80 13 00 00 04 7e 13 00 00 04 72 90 01 01 03 00 70 28 1e 00 00 0a 28 55 00 00 0a 7e 0e 00 00 04 72 90 01 01 03 00 70 7e 0c 00 00 04 72 90 01 01 00 00 70 28 21 00 00 0a 6f 27 00 00 06 de 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}