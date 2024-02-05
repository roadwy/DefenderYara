
rule Trojan_BAT_AgentTesla_EXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 41 00 56 00 41 00 77 00 47 00 41 00 68 00 42 00 77 00 5a 00 41 00 55 00 47 00 41 00 4d 00 42 00 51 00 22 06 45 00 22 06 71 00 22 06 22 06 59 00 44 00 41 00 78 00 22 06 4d 00 41 00 49 00 } //01 00 
		$a_01_1 = {6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 } //01 00 
		$a_01_2 = {54 00 6f 00 43 00 68 00 61 00 72 00 41 00 72 00 72 00 61 00 79 00 } //01 00 
		$a_01_3 = {00 46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 00 } //01 00 
		$a_01_4 = {00 56 30 30 30 30 30 30 30 30 30 30 30 30 30 35 00 } //00 00 
	condition:
		any of ($a_*)
 
}