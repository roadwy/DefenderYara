
rule Trojan_BAT_AgentTesla_LTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 31 63 33 72 73 74 72 69 6d 2f 77 61 72 2f 74 65 6e 2e 6e 69 62 74 78 65 74 2f 2f 3a 73 70 74 74 68 } //01 00 
		$a_81_1 = {53 74 72 52 65 76 65 72 73 65 } //01 00 
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00 
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_4 = {53 70 6c 69 74 } //01 00 
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}