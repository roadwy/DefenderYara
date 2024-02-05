
rule Trojan_BAT_AgentTesla_JRB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 05 17 d6 13 05 90 00 } //01 00 
		$a_81_1 = {38 37 65 32 31 34 33 61 2d 38 63 62 39 2d 34 36 32 66 2d 38 34 61 61 2d 63 37 38 65 30 30 62 64 66 39 37 61 } //01 00 
		$a_81_2 = {00 58 58 58 58 58 58 00 } //01 00 
		$a_81_3 = {00 57 53 53 00 } //01 00 
		$a_81_4 = {67 65 74 5f 50 61 72 61 6d 41 72 72 61 79 30 } //00 00 
	condition:
		any of ($a_*)
 
}