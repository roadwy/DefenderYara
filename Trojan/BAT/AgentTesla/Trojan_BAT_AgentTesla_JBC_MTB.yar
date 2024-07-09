
rule Trojan_BAT_AgentTesla_JBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {0b 07 16 73 ?? ?? ?? 0a 0c 20 ?? ?? ?? 00 8d ?? ?? ?? 01 0d 38 ?? ?? ?? 00 06 09 16 11 04 6f ?? ?? ?? 0a 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 3d ?? ?? ?? ?? 06 6f ?? ?? ?? 0a 13 05 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}