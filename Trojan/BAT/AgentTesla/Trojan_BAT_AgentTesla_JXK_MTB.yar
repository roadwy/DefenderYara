
rule Trojan_BAT_AgentTesla_JXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 08 28 ?? ?? ?? 0a 04 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 07 17 d6 0b 07 03 6f ?? ?? ?? 0a fe 04 0d 09 2d cc } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}