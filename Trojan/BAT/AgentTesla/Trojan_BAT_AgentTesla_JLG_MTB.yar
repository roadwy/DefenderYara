
rule Trojan_BAT_AgentTesla_JLG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 } //01 00 
		$a_01_1 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //01 00 
		$a_81_2 = {00 46 54 50 00 53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 00 54 00 67 65 74 5f 68 75 6d 4d 41 58 00 } //01 00 
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_81_4 = {4f 64 64 73 4d 69 73 73 69 6f 6e 43 6f 6e 74 72 6f 6c } //01 00 
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_6 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_81_7 = {4c 61 74 65 47 65 74 } //01 00 
		$a_81_8 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}