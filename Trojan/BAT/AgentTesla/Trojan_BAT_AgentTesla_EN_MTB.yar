
rule Trojan_BAT_AgentTesla_EN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 90 01 05 28 90 01 04 28 90 01 04 04 07 90 01 05 28 90 01 04 6a 61 b7 28 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 35 35 65 63 31 61 65 38 2d 34 66 62 39 2d 34 34 64 61 2d 39 65 65 30 2d 38 35 39 34 66 63 64 31 36 62 34 35 } //14 00 
		$a_81_1 = {4d 75 6c 74 69 70 6c 61 79 65 72 4c 69 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_2 = {46 41 54 41 4c 20 45 52 52 4f 52 21 20 47 4f 20 54 4f 20 48 45 4c 4c 21 } //01 00 
		$a_81_3 = {65 78 70 6c 6f 73 69 6f 6e 2e 70 6e 67 } //01 00 
		$a_81_4 = {73 6b 75 6c 6c 73 2e 70 6e 67 } //01 00 
		$a_81_5 = {41 61 61 61 61 61 72 67 68 21 } //01 00 
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}