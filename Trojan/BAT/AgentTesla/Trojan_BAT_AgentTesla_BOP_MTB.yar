
rule Trojan_BAT_AgentTesla_BOP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {26 20 00 00 00 00 38 ?? ?? ?? ?? 11 00 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 20 00 01 00 00 14 11 00 17 8d ?? ?? ?? 01 25 16 02 7e ?? ?? ?? 04 28 ?? ?? ?? 06 a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 28 ?? ?? ?? 06 13 01 38 ?? ?? ?? ?? 28 ?? ?? ?? 0a 13 00 38 } //1
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_5 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}