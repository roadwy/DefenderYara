
rule Trojan_BAT_AgentTesla_LID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 06 17 58 0a 06 1f 0a 32 ed } //01 00 
		$a_01_1 = {61 62 33 34 37 66 62 36 2d 32 37 65 36 2d 34 34 36 65 2d 62 61 65 62 2d 63 33 66 31 } //01 00 
		$a_01_2 = {45 6e 63 6f 64 65 72 } //01 00 
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00 
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}