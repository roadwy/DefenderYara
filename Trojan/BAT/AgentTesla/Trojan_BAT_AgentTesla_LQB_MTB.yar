
rule Trojan_BAT_AgentTesla_LQB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 64 64 73 68 73 73 74 61 64 61 61 61 64 77 73 73 73 73 73 67 2e 64 6c 6c 23 } //01 00 
		$a_01_1 = {23 66 61 73 64 66 67 73 66 73 64 2e 64 6c 6c 23 } //01 00 
		$a_01_2 = {23 68 6b 6b 6b 6b 6b 68 23 } //01 00 
		$a_01_3 = {23 66 6c 6a 67 61 66 2e 64 6c 6c 23 } //01 00 
		$a_01_4 = {23 66 2e 64 67 64 64 6a 6b 64 6c 6c 23 } //01 00 
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}