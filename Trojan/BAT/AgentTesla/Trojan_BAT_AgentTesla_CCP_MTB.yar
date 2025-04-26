
rule Trojan_BAT_AgentTesla_CCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 28 ?? ?? ?? 0a 08 11 04 18 5d 17 d6 28 ?? ?? ?? 0a da 13 05 07 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 11 04 17 d6 13 04 11 04 09 31 cb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_CCP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {42 46 35 34 41 36 38 34 2d 39 33 41 44 2d 34 35 42 34 2d 42 46 31 39 2d 38 37 42 31 30 43 39 42 36 30 32 46 } //1 BF54A684-93AD-45B4-BF19-87B10C9B602F
		$a_81_1 = {49 45 78 70 61 6e 64 6f } //1 IExpando
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}