
rule Trojan_BAT_AgentTesla_LUC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff ?? ?? ?? ?? ?? ?? 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a } //1
		$a_01_1 = {0a 0d 06 09 28 8b 00 00 0a 0a 08 17 d6 0c 08 07 6f 8c 00 00 0a 32 d9 } //1
		$a_03_2 = {0a 0d 06 09 28 ?? ?? ?? 0a 0a 08 17 d6 0c 08 07 6f ?? ?? ?? 0a 32 d9 } //1
		$a_01_3 = {64 00 5f 00 ac 00 5f 00 5f 00 71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f 00 97 00 70 00 5f 00 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}