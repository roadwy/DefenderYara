
rule Trojan_BAT_AgentTesla_ABMT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b de 03 26 de d4 90 0a 2b 00 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b de 03 26 de d4 } //5
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}