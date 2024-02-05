
rule Trojan_BAT_AgentTesla_NEAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 28 19 00 00 06 28 06 00 00 06 74 02 00 00 01 28 05 00 00 06 74 01 00 00 1b 28 03 00 00 06 0a dd 03 00 00 00 26 de d8 06 2a } //05 00 
		$a_01_1 = {02 25 16 02 8e 69 28 02 00 00 0a 2a } //02 00 
		$a_01_2 = {41 46 6f 72 67 65 2e 56 69 64 65 6f } //02 00 
		$a_01_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}