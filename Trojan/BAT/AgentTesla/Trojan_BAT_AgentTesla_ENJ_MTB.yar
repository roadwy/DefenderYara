
rule Trojan_BAT_AgentTesla_ENJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5f 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //01 00 
		$a_01_1 = {00 49 44 65 66 65 72 72 65 64 00 } //01 00 
		$a_01_2 = {00 54 77 6f 44 69 67 69 74 59 65 61 72 4d 61 78 00 } //01 00 
		$a_01_3 = {00 46 69 65 6c 64 00 } //01 00 
		$a_01_4 = {00 47 65 74 54 79 70 65 } //01 00 
		$a_01_5 = {00 43 6c 65 61 6e 75 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}