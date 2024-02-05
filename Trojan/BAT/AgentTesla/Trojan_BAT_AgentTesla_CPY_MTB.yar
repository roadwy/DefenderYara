
rule Trojan_BAT_AgentTesla_CPY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_01_4 = {54 6f 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}