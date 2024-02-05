
rule Trojan_BAT_AgentTesla_DGJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 30 39 36 38 35 37 66 36 2d 32 33 63 33 2d 34 31 65 33 2d 62 39 36 34 2d 30 63 30 64 30 32 66 36 65 31 38 33 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00 
		$a_01_3 = {00 47 65 74 50 69 78 65 6c 00 } //01 00 
		$a_01_4 = {00 54 6f 57 69 6e 33 32 00 } //01 00 
		$a_01_5 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}