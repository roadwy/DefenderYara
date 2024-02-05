
rule Trojan_BAT_AgentTesla_NSC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 1a 00 00 0a 0b 06 16 73 1b 00 00 0a 73 1c 00 00 0a 0c 08 07 6f 1d 00 00 0a 07 6f 1e 00 00 0a 0d de 1e } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}