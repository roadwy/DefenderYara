
rule Trojan_BAT_AgentTesla_NTA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 28 18 00 00 06 26 7e 90 01 03 04 18 6f 90 01 03 0a 00 02 28 90 01 03 06 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {53 70 6c 61 73 68 54 65 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NTA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 73 00 53 00 73 00 4d 00 6d 00 42 00 } //01 00 
		$a_01_1 = {40 00 53 00 79 00 73 00 74 00 65 00 6d 00 40 00 2e 00 40 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 40 00 2e 00 40 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 40 00 } //01 00 
		$a_81_2 = {40 4c 6f 61 64 40 } //01 00 
		$a_81_3 = {4d 65 74 68 6f 64 30 } //01 00 
		$a_81_4 = {54 6f 49 6e 74 65 67 65 72 } //01 00 
		$a_81_5 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}