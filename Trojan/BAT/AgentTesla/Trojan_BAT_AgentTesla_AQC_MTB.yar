
rule Trojan_BAT_AgentTesla_AQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 0b 11 04 06 07 90 01 05 13 05 11 05 90 01 05 13 06 09 08 11 06 b4 9c 07 17 d6 0b 07 16 31 de 08 17 d6 0c 06 17 d6 0a 06 90 00 } //0a 00 
		$a_02_1 = {25 16 09 a2 25 17 90 01 05 a2 25 13 04 14 14 18 90 01 05 25 16 17 9c 25 13 05 17 90 01 05 26 11 05 16 91 2d 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AQC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 03 08 03 90 01 05 5d 17 d6 90 01 05 da 0d 06 09 90 01 05 13 04 12 04 90 01 05 28 90 01 03 06 0a 00 08 17 d6 0c 08 07 fe 02 16 fe 01 13 05 11 05 2d be 06 13 06 2b 00 11 06 2a 90 00 } //01 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_2 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //LateBinding  01 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  00 00 
	condition:
		any of ($a_*)
 
}