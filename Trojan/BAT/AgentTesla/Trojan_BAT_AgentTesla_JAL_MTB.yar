
rule Trojan_BAT_AgentTesla_JAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {39 66 33 39 32 37 32 37 2d 31 65 30 30 2d 34 65 62 30 2d 61 36 32 39 2d 64 64 65 32 30 63 62 31 63 65 64 37 } //1 9f392727-1e00-4eb0-a629-dde20cb1ced7
		$a_81_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {50 6f 72 74 61 6c 71 75 69 7a } //1 Portalquiz
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_6 = {54 69 6d 65 72 5f 74 69 63 6b } //1 Timer_tick
		$a_81_7 = {53 70 6c 69 74 } //1 Split
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_9 = {46 75 6e 63 74 69 6f 6e 49 6e 69 74 } //1 FunctionInit
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_12 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}