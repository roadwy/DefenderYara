
rule Trojan_BAT_AgentTesla_EXY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {37 36 34 38 48 32 38 } //01 00 
		$a_81_1 = {46 35 45 4a 34 38 46 46 47 48 55 35 35 54 36 } //01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}