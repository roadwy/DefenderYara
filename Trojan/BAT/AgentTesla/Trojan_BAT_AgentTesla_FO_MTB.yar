
rule Trojan_BAT_AgentTesla_FO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {02 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 16 0d 2b 18 02 08 02 08 91 06 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e2 08 17 58 0c 08 02 8e 69 32 c5 } //01 00 
		$a_81_1 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00 
		$a_81_2 = {44 65 63 72 79 70 74 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_FO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {70 12 01 28 90 01 03 0a 2c 10 07 16 31 0c 07 20 e8 03 00 00 5a 28 90 01 03 0a de 03 90 09 06 00 16 0b 72 90 00 } //05 00 
		$a_03_1 = {26 de 00 72 90 01 03 70 28 90 01 03 0a 73 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 74 01 00 00 1b 28 90 01 03 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 14 16 8d 01 00 00 01 6f 90 01 03 0a 26 de 03 26 de 00 2a 90 00 } //01 00 
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_4 = {43 6f 6e 76 65 72 74 } //01 00 
		$a_81_5 = {43 6f 6e 63 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}