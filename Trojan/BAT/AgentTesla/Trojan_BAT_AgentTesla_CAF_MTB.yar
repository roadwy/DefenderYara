
rule Trojan_BAT_AgentTesla_CAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } //01 00 
		$a_02_1 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 06 28 90 01 03 06 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CAF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {2b 1d 12 03 2b 1c 2b 21 07 02 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a de 20 08 2b e0 28 90 01 01 00 00 0a 2b dd 06 2b dc 90 00 } //01 00 
		$a_01_1 = {54 6f 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CAF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 11 04 1f 10 28 90 01 03 06 d1 28 90 01 03 06 26 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00 
		$a_81_5 = {54 6f 49 6e 74 33 32 } //01 00 
		$a_81_6 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //01 00 
		$a_81_7 = {67 65 74 5f 52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}