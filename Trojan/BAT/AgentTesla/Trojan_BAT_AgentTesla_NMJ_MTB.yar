
rule Trojan_BAT_AgentTesla_NMJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 67 64 73 67 64 68 66 64 67 67 67 67 67 67 64 6b 6b 73 67 2e 64 6c 6c 23 } //01 00 
		$a_01_1 = {23 64 66 67 2e 64 70 6f 6c 70 6c 6c 23 } //01 00 
		$a_01_2 = {23 67 73 64 66 67 67 66 67 73 64 2e 64 6c 6c 23 } //01 00 
		$a_01_3 = {23 66 64 2e 70 64 6c 6c 23 } //01 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}