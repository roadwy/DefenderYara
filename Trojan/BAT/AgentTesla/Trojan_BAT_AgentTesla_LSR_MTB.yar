
rule Trojan_BAT_AgentTesla_LSR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 00 } //01 00 
		$a_01_1 = {00 5f 4a 4a 30 00 } //01 00 
		$a_01_2 = {00 5f 4a 4a 31 00 } //01 00 
		$a_01_3 = {00 5f 4a 4a 34 00 } //01 00 
		$a_01_4 = {00 5f 4a 4a 35 00 } //01 00 
		$a_01_5 = {00 5f 4a 4a 36 00 } //01 00 
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_7 = {42 75 6e 69 66 75 5f 54 } //01 00 
		$a_81_8 = {65 78 74 42 6f 78 } //00 00 
	condition:
		any of ($a_*)
 
}