
rule Trojan_BAT_AgentTesla_BRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 74 ?? ?? ?? 01 16 73 ?? ?? ?? 0a 0c 1a 8d ?? ?? ?? 01 0d 07 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 07 14 72 ?? ?? ?? 70 16 8d ?? ?? ?? 01 14 14 14 28 ?? ?? ?? 0a 1b 8c ?? ?? ?? 01 28 ?? ?? ?? 0a a2 14 14 28 f0 00 00 0a 00 07 28 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}