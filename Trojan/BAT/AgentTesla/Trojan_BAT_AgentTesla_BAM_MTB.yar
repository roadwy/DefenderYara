
rule Trojan_BAT_AgentTesla_BAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 14 72 3a 3f 02 70 18 8d 90 01 01 00 00 01 25 16 72 4a 3f 02 70 a2 25 17 72 4e 3f 02 70 a2 14 14 14 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BAM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 00 49 6e 76 6f 6b 65 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_81_6 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_81_7 = {5f 4e 5f 00 41 45 53 5f 44 65 63 72 79 70 74 } //01 00 
		$a_81_8 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00 
		$a_81_9 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}