
rule Trojan_BAT_AgentTesla_COG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.COG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 46 5f 32 5f 32 5f 32 5f 32 5f 32 00 } //01 00 
		$a_01_1 = {00 46 5f 37 5f 37 5f 37 5f 37 5f 37 00 } //01 00 
		$a_01_2 = {00 51 5f 38 5f 51 5f 38 5f 51 5f 38 00 } //01 00 
		$a_01_3 = {00 58 5f 30 5f 30 5f 30 5f 30 5f 30 00 } //01 00 
		$a_01_4 = {00 5a 36 36 36 36 36 36 36 36 36 36 36 36 36 00 } //01 00  娀㘶㘶㘶㘶㘶㘶6
		$a_01_5 = {00 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 33 33 33 33 33 33 33 33 00 } //01 00 
		$a_01_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_8 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_9 = {54 6f 49 6e 74 36 34 } //00 00  ToInt64
	condition:
		any of ($a_*)
 
}