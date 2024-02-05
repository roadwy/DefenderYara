
rule Trojan_BAT_AgentTesla_NEF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 20 6c 2e 64 6c 54 } //01 00 
		$a_01_1 = {56 6a 73 6f 66 6f 2e 65 78 65 } //01 00 
		$a_01_2 = {67 00 6f 00 61 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_3 = {30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 } //01 00 
		$a_01_4 = {47 00 6f 00 61 00 73 00 64 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}