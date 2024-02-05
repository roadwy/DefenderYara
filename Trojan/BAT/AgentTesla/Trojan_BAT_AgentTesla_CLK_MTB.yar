
rule Trojan_BAT_AgentTesla_CLK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 05 17 d6 13 05 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //01 00 
		$a_01_4 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00 
		$a_01_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}