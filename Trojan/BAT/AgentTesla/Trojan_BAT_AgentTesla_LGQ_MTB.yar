
rule Trojan_BAT_AgentTesla_LGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_4 = {46 6f 72 6d 31 41 53 46 46 44 53 53 46 53 46 } //01 00 
		$a_01_5 = {46 72 6f 6d 41 72 67 62 } //00 00 
	condition:
		any of ($a_*)
 
}