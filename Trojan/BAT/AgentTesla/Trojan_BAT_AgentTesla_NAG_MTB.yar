
rule Trojan_BAT_AgentTesla_NAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0f 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 13 01 90 00 } //01 00 
		$a_01_1 = {68 6a 6b 6a 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 72 23 00 00 70 6f 90 01 03 0a 00 02 02 fe 90 01 04 06 73 90 01 03 0a 28 90 01 03 0a 00 02 16 28 90 01 03 0a 00 2a 90 00 } //01 00 
		$a_01_1 = {47 50 54 34 5f 56 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAG_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 2b 52 00 08 09 11 04 28 90 01 03 06 13 07 d0 90 01 03 01 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 17 8d 90 01 03 01 25 16 11 07 8c 90 01 03 01 a2 28 90 01 03 0a a5 90 01 03 01 13 08 17 13 09 07 11 08 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d a3 06 17 58 0a 00 09 90 00 } //01 00 
		$a_01_1 = {49 5f 5f 5f 5f 5f 5f 5f 49 } //00 00 
	condition:
		any of ($a_*)
 
}