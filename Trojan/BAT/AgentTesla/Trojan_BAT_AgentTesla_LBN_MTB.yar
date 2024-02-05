
rule Trojan_BAT_AgentTesla_LBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_5 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}