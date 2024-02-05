
rule Trojan_BAT_AgentTesla_NW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 02 72 90 01 01 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0a dd 06 00 00 00 90 00 } //01 00 
		$a_01_1 = {45 69 68 6f 72 67 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 11 0e 17 da 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 09 11 0e 09 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 06 da 13 0f 11 04 11 0f 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 13 04 11 0e 17 d6 13 0e 11 0e 11 0d 31 a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NW_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 6f 75 72 41 72 } //01 00 
		$a_81_1 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //01 00 
		$a_81_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //01 00 
		$a_81_3 = {49 56 65 63 74 6f 72 5f 52 61 77 } //01 00 
		$a_81_4 = {4b 65 79 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00 
		$a_81_5 = {53 74 72 52 65 76 65 72 73 65 } //01 00 
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00 
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00 
		$a_81_8 = {4c 6f 67 69 6e 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}