
rule Trojan_BAT_AgentTesla_AML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5f 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5f 44 65 76 65 6c 6f 70 6d 65 6e 74 2e 70 64 62 } //01 00 
		$a_01_1 = {67 65 74 5f 41 64 64 72 65 73 73 00 73 65 74 5f 41 64 64 72 65 73 73 00 74 78 74 41 64 64 72 65 73 73 } //01 00 
		$a_01_2 = {53 79 73 74 65 6d 2e 44 61 74 61 00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00 64 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}