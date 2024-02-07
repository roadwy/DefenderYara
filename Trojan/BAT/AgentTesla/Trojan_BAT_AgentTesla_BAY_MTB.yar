
rule Trojan_BAT_AgentTesla_BAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 01 00 00 0a 0c 08 16 08 8e 69 28 90 01 01 00 00 0a 08 0d de 1b 26 20 88 13 00 00 28 90 01 01 00 00 0a de 00 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BAY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 18 18 8d 90 01 03 01 25 16 11 0a 8c 90 01 03 01 a2 25 17 11 0b 8c 90 01 03 01 a2 28 90 01 03 0a 25 2d 0d 26 12 20 90 01 06 11 20 2b 05 90 01 05 13 1e 11 1e 28 90 01 03 0a 13 1f 07 06 11 1f b4 9c 11 0b 17 d6 13 0b 11 0b 11 1d 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}