
rule Trojan_BAT_AgentTesla_JTD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //01 00 
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_81_2 = {49 6d 61 63 } //01 00 
		$a_81_3 = {49 70 68 6f 6e 65 } //01 00 
		$a_81_4 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}