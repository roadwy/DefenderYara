
rule Trojan_BAT_AgentTesla_GW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 62 38 61 63 35 37 34 35 2d 35 31 36 62 2d 34 37 36 36 2d 39 38 64 39 2d 65 36 62 38 35 37 32 63 35 30 66 37 } //20 $b8ac5745-516b-4766-98d9-e6b8572c50f7
		$a_81_1 = {24 35 62 32 34 62 39 62 38 2d 62 37 36 36 2d 34 61 31 61 2d 62 30 39 39 2d 32 35 39 30 66 38 65 64 36 31 30 38 } //20 $5b24b9b8-b766-4a1a-b099-2590f8ed6108
		$a_81_2 = {24 36 35 38 62 62 37 30 63 2d 66 63 30 65 2d 34 64 31 33 2d 38 63 37 35 2d 30 66 30 36 32 30 30 30 38 64 65 39 } //20 $658bb70c-fc0e-4d13-8c75-0f0620008de9
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=23
 
}