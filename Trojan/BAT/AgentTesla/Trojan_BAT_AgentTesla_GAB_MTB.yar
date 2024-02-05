
rule Trojan_BAT_AgentTesla_GAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 36 2b 37 de 3e 0a 2b de 0b 2b e7 28 90 01 01 00 00 0a 2b ed 28 90 01 01 00 00 06 2b c9 28 90 01 01 00 00 0a 2b c8 06 2b c7 6f 90 01 01 00 00 0a 2b c2 28 90 01 01 00 00 0a 2b bd 07 2b c0 07 2b c0 07 2b c7 0c 2b c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_GAB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 6c 00 75 00 65 00 6e 00 63 00 65 00 2e 00 46 00 6c 00 75 00 65 00 6e 00 63 00 65 00 } //01 00 
		$a_01_1 = {46 00 6c 00 75 00 65 00 6e 00 63 00 65 00 73 00 } //01 00 
		$a_01_2 = {42 00 49 00 47 00 42 00 4f 00 53 00 53 00 } //01 00 
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_81_5 = {49 6e 76 6f 6b 65 } //01 00 
		$a_81_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_81_7 = {54 6f 41 72 72 61 79 } //01 00 
		$a_81_8 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00 
		$a_81_9 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_81_10 = {52 65 76 65 72 73 65 } //01 00 
		$a_81_11 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}