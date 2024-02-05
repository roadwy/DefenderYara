
rule Trojan_BAT_AgentTesla_PSB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 00 16 11 00 8e 69 6f 90 01 04 13 04 38 90 01 04 73 90 01 04 13 01 20 90 01 04 38 90 01 04 11 05 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}