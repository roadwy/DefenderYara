
rule Trojan_BAT_AgentTesla_EAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 5c 9d 6f ?? 00 00 0a 25 8e 69 18 59 0b 07 9a 0a de 03 26 de 00 06 2a } //1
		$a_03_1 = {16 0a 2b 36 7e ?? 00 00 04 06 7e ?? 00 00 04 06 9a 1b 28 } //1
		$a_03_2 = {0a a2 06 17 58 0a 06 7e ?? 00 00 04 8e 69 32 c0 } //1
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 13 05 38 ?? 00 00 00 11 01 11 02 11 01 11 03 91 9c 20 03 00 00 00 fe ?? 06 00 38 ?? ff ff ff 11 01 11 03 11 04 9c 38 ?? 00 00 00 11 03 17 59 13 03 20 02 00 00 00 7e ?? 06 00 04 7b ?? 06 00 04 39 ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 11 01 11 02 91 13 04 38 ?? ff ff ff 11 02 17 58 13 02 20 00 00 00 00 7e } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}