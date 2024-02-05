
rule Trojan_BAT_AgentTesla_LHE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //01 00 
		$a_01_1 = {45 6e 63 6f 64 65 72 } //01 00 
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}