
rule Trojan_BAT_AgentTesla_HGN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 03 a2 14 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0a 02 06 72 ?? ?? ?? 70 18 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 7d ?? ?? ?? 04 2a } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}