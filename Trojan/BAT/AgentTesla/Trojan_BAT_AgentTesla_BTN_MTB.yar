
rule Trojan_BAT_AgentTesla_BTN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {9e 02 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 94 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 94 58 20 00 01 00 00 5d 94 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 02 7b ?? ?? ?? 04 03 02 7b ?? ?? ?? 04 91 02 7b ?? ?? ?? 04 61 d2 9c 02 02 7b ?? ?? ?? 04 17 58 7d ?? ?? ?? 04 02 7b ?? ?? ?? 04 03 8e 69 } //1
		$a_81_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_2 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //1 AssemblyResolve
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}