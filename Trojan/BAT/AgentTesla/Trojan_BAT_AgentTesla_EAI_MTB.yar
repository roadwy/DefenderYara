
rule Trojan_BAT_AgentTesla_EAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 25 9d 6f ?? 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 0d 2b 11 08 09 07 09 9a 1f 10 28 ?? 00 00 0a 9c 09 17 58 0d 09 07 8e 69 32 e9 } //3
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_2 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EAI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 ?? ?? ?? 0a 20 9e 02 00 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b3 90 09 0c 00 08 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a } //1
		$a_01_1 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
		$a_01_2 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}