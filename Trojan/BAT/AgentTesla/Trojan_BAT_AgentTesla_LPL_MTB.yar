
rule Trojan_BAT_AgentTesla_LPL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {58 64 72 73 62 79 61 6f 70 62 2e 64 6c 6c } //01 00 
		$a_01_1 = {68 71 75 6b 6e 69 76 73 6c 71 6b 62 2e 64 6c 6c } //01 00 
		$a_01_2 = {6c 6a 6e 68 62 75 6d 70 74 78 72 77 68 68 67 } //01 00 
		$a_01_3 = {66 63 6b 61 6a 6d 77 71 71 73 67 74 79 70 6d 77 6e } //01 00 
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}