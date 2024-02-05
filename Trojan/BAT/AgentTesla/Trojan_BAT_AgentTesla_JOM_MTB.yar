
rule Trojan_BAT_AgentTesla_JOM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 41 41 31 32 33 } //01 00 
		$a_81_1 = {00 4f 4f 4f 4f 4f 00 } //01 00 
		$a_81_2 = {41 32 33 35 34 38 } //01 00 
		$a_81_3 = {41 36 35 34 36 } //01 00 
		$a_81_4 = {41 36 38 37 39 } //01 00 
		$a_81_5 = {41 39 32 38 33 } //01 00 
		$a_81_6 = {53 70 6c 69 74 } //01 00 
		$a_81_7 = {54 6f 44 6f 75 62 6c 65 } //01 00 
		$a_81_8 = {52 6f 75 6e 64 } //01 00 
		$a_81_9 = {54 6f 53 74 72 69 6e 67 } //01 00 
		$a_81_10 = {41 70 70 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}