
rule Trojan_BAT_AgentTesla_NSI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {33 2e 37 30 2e 32 34 37 2e 32 32 39 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}