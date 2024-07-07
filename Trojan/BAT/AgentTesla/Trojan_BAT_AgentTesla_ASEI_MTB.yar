
rule Trojan_BAT_AgentTesla_ASEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 00 37 00 38 00 34 00 4a 00 41 00 37 00 47 00 41 00 38 00 34 00 38 00 49 00 34 00 45 00 52 00 38 00 44 00 37 00 47 00 48 00 35 00 } //2 F784JA7GA848I4ER8D7GH5
		$a_01_1 = {4a 00 65 00 6f 00 70 00 61 00 72 00 64 00 79 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 Jeopardy.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}