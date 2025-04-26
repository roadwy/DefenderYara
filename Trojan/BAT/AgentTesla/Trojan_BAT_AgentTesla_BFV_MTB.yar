
rule Trojan_BAT_AgentTesla_BFV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {06 16 9a 18 3a ?? ?? ?? ?? 26 38 ?? ?? ?? ?? 11 01 02 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 11 00 11 01 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 1e 3a ?? ?? ?? ?? 26 11 02 17 8d ?? ?? ?? 01 25 16 02 28 ?? ?? ?? 06 a2 6f ?? ?? ?? 0a 74 } //10
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //1 ClassLibrary1
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}