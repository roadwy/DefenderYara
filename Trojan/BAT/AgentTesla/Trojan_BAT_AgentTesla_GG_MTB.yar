
rule Trojan_BAT_AgentTesla_GG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {5a 4a 34 46 41 37 45 5a 37 35 45 43 55 4a 42 5a } //01 00 
		$a_81_1 = {46 6c 6f 72 61 } //01 00 
		$a_81_2 = {42 69 74 6d 61 70 } //01 00 
		$a_81_3 = {46 69 7a 7a 42 75 7a 7a } //01 00 
		$a_81_4 = {63 6f 6e 76 65 72 74 } //01 00 
		$a_81_5 = {44 65 62 75 67 67 65 72 } //01 00 
		$a_81_6 = {49 73 4c 6f 67 67 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}