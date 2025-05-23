
rule Trojan_BAT_AgentTesla_HJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0e 00 00 "
		
	strings :
		$a_00_0 = {24 35 64 33 66 35 36 62 30 2d 30 63 61 38 2d 34 61 35 66 2d 61 64 32 37 2d 62 62 35 65 63 61 63 35 65 34 39 64 } //20 $5d3f56b0-0ca8-4a5f-ad27-bb5ecac5e49d
		$a_00_1 = {24 39 37 63 35 61 32 65 35 2d 33 38 62 31 2d 34 33 31 33 2d 39 33 61 34 2d 31 33 39 63 36 64 30 36 39 61 34 39 } //20 $97c5a2e5-38b1-4313-93a4-139c6d069a49
		$a_00_2 = {24 34 61 34 33 61 65 38 31 2d 37 61 30 63 2d 34 66 39 66 2d 61 32 33 30 2d 65 38 35 65 31 33 30 63 35 37 34 61 } //20 $4a43ae81-7a0c-4f9f-a230-e85e130c574a
		$a_00_3 = {24 38 65 36 61 38 32 64 36 2d 66 33 66 64 2d 34 34 65 61 2d 38 34 35 33 2d 33 62 31 63 36 39 31 32 35 37 37 32 } //20 $8e6a82d6-f3fd-44ea-8453-3b1c69125772
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_11 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_13 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*20+(#a_00_2  & 1)*20+(#a_00_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=24
 
}