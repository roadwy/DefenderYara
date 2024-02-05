
rule Trojan_BAT_AgentTesla_COY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.COY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 04 17 58 13 04 11 04 08 8e 69 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {54 6f 42 79 74 65 } //01 00 
		$a_01_4 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_01_5 = {50 61 72 61 6d 58 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}