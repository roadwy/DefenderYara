
rule Trojan_BAT_AgentTesla_NRT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 72 69 65 75 74 69 6e 2e 63 6f 6d 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //trieutin.com/loader/uploads/  01 00 
		$a_01_1 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}