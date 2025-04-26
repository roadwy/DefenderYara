
rule Trojan_BAT_AgentTesla_JXA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {73 65 73 73 69 6f 6e 2e 73 65 73 } //1 session.ses
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_2 = {35 61 35 39 38 32 35 36 2d 34 38 66 61 2d 34 39 30 66 2d 61 35 62 33 2d 37 61 62 63 32 32 33 33 32 36 31 39 } //1 5a598256-48fa-490f-a5b3-7abc22332619
		$a_01_3 = {6d 75 79 6f 75 20 4c 69 62 } //1 muyou Lib
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 44 69 73 70 6c 61 79 41 74 74 72 69 62 75 74 65 } //1 DebuggerDisplayAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}