
rule Trojan_BAT_AgentTesla_NQU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 76 65 72 63 72 61 66 74 5f 6d 6f 64 65 6c 2e 43 68 61 72 61 63 74 65 72 } //1 Evercraft_model.Character
		$a_81_1 = {53 79 73 33 32 5f 32 34 33 34 34 } //1 Sys32_24344
		$a_81_2 = {53 79 73 33 32 5f 32 34 33 38 34 } //1 Sys32_24384
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {4c 00 6f 00 61 00 64 } //1
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}