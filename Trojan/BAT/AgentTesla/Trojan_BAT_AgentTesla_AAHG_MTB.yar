
rule Trojan_BAT_AgentTesla_AAHG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 72 0d 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 13 00 38 90 00 } //01 00 
		$a_01_1 = {34 00 35 00 2e 00 31 00 32 00 2e 00 32 00 35 00 33 00 2e 00 31 00 34 00 37 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00  ReadAsByteArrayAsync
	condition:
		any of ($a_*)
 
}