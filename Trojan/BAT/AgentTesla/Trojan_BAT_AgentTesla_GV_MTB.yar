
rule Trojan_BAT_AgentTesla_GV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 33 31 39 34 65 36 35 64 2d 63 64 32 62 2d 34 32 63 37 2d 61 61 34 66 2d 62 65 33 37 63 65 66 38 33 61 64 63 } //20 $3194e65d-cd2b-42c7-aa4f-be37cef83adc
		$a_81_1 = {24 64 61 37 32 35 30 30 35 2d 35 63 32 36 2d 34 33 37 36 2d 62 61 32 36 2d 32 64 32 31 30 38 32 39 62 32 34 39 } //20 $da725005-5c26-4376-ba26-2d210829b249
		$a_81_2 = {24 62 37 63 61 66 35 64 36 2d 31 34 61 35 2d 34 61 30 30 2d 62 39 30 61 2d 39 31 31 63 66 36 33 36 39 33 34 30 } //20 $b7caf5d6-14a5-4a00-b90a-911cf6369340
		$a_81_3 = {24 62 35 66 61 62 36 31 34 2d 66 66 64 63 2d 34 32 66 32 2d 62 63 36 33 2d 66 31 63 33 64 61 31 33 32 37 30 36 } //20 $b5fab614-ffdc-42f2-bc63-f1c3da132706
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=23
 
}