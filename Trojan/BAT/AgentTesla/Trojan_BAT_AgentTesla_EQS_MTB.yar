
rule Trojan_BAT_AgentTesla_EQS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {38 00 38 00 59 00 43 00 51 00 4f 00 39 00 47 00 48 00 48 00 50 00 47 00 44 00 59 00 48 00 34 00 5a 00 47 00 48 00 42 00 51 00 38 00 } //05 00 
		$a_01_1 = {46 00 69 00 72 00 65 00 4c 00 61 00 6d 00 70 00 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_EQS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 08 95 28 90 01 03 0a 0d 09 8e 69 17 da 13 04 16 13 05 2b 12 06 08 1a d8 11 05 d6 09 11 05 91 9c 11 05 17 d6 13 05 11 05 11 04 31 e8 08 17 d6 0c 90 00 } //0a 00 
		$a_03_1 = {06 08 02 08 91 03 08 03 6f 90 01 03 30 0a 5d 6f 90 01 03 0a 28 90 01 03 0a 61 9c 08 17 d6 0c 90 00 } //01 00 
		$a_01_2 = {00 47 65 74 4d 65 74 68 6f 64 00 } //01 00 
		$a_01_3 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}