
rule Trojan_BAT_AgentTesla_JXI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 78 6e 78 76 78 6f 78 6b 78 65 } //01 00 
		$a_81_1 = {67 6e 69 72 74 53 34 36 65 73 61 42 6d 6f 72 46 } //01 00 
		$a_81_2 = {74 72 65 76 6e 6f 43 2e 6d 65 74 73 79 53 } //01 00 
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 } //01 00 
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_5 = {53 74 72 52 65 76 65 72 73 65 } //01 00 
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}