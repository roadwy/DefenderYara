
rule Trojan_BAT_AgentTesla_BDT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 02 28 ?? ?? ?? 06 a2 28 ?? ?? ?? 06 74 ?? ?? ?? 01 13 ?? 16 7e ?? ?? ?? 04 ?? ?? ?? ?? ?? 26 1b ?? ?? ?? ?? ?? 09 6f ?? ?? ?? 0a 08 20 00 01 00 00 14 09 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 64 6c 6c } //1 ClassLibrary1.dll
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {53 74 75 62 53 74 61 74 75 73 53 74 72 61 74 65 67 79 } //1 StubStatusStrategy
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}