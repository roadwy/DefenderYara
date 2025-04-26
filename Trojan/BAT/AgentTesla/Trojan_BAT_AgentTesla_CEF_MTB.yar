
rule Trojan_BAT_AgentTesla_CEF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {b0 00 d5 00 b2 00 b3 00 cf 00 e6 00 dc 00 af 00 ae 00 ae 00 dd 00 e3 00 b9 00 d4 00 b2 00 ae 00 b0 00 d4 00 d4 00 dc 00 e1 00 be 00 ae 00 ae 00 b0 00 d5 00 b6 00 b6 00 } //1
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_7 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //1 ThreadPool.Light
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}