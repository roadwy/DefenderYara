
rule Trojan_BAT_AgentTesla_NGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 00 32 00 32 00 33 00 32 00 31 00 33 00 31 00 32 00 78 00 30 00 30 00 30 00 32 00 33 00 33 00 32 } //01 00 
		$a_01_1 = {68 64 66 66 64 65 65 66 61 73 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_01_5 = {52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}