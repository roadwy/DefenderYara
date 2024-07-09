
rule Trojan_BAT_AgentTesla_NBL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 0a 2b 00 06 2a } //5
		$a_01_1 = {42 00 75 00 6e 00 00 0d 69 00 66 00 75 00 5f 00 54 00 65 00 00 07 78 00 74 00 42 00 00 05 6f 00 78 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_BAT_AgentTesla_NBL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 18 7e 9f 00 00 04 1f 72 7e 9f 00 00 04 1f 72 93 7e 9f 00 00 04 20 00 01 00 00 93 61 20 cb 00 00 00 5f 9d 2e 09 } //1
		$a_03_1 = {04 20 ab 52 e3 48 61 02 61 0a 7e b0 ?? ?? ?? 0c 08 74 44 ?? ?? ?? 25 06 93 0b 06 18 58 93 07 61 0b 18 13 0e 38 7c ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}