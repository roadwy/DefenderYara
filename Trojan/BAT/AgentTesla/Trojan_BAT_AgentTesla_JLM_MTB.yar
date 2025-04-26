
rule Trojan_BAT_AgentTesla_JLM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0a 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 72 ?? ?? ?? 70 28 ?? ?? ?? ?? 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 18 8d ?? ?? ?? 01 25 16 07 11 05 18 d8 18 6f ?? ?? ?? 0a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 9c 11 05 17 d6 13 05 11 05 11 04 31 b2 } //10
		$a_81_1 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 00 53 00 53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //10
		$a_81_2 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_81_3 = {54 6f 42 79 74 65 } //1 ToByte
		$a_81_4 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_81_5 = {52 6f 75 6e 64 } //1 Round
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_7 = {67 65 74 5f 50 61 72 61 6d 41 72 72 61 79 30 } //1 get_ParamArray0
		$a_81_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=18
 
}