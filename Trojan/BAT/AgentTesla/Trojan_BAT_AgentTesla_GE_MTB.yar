
rule Trojan_BAT_AgentTesla_GE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_1 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_01_2 = {46 75 63 6b 69 6e 67 53 68 69 74 } //3 FuckingShit
		$a_00_3 = {46 00 75 00 63 00 6b 00 69 00 6e 00 67 00 53 00 68 00 69 00 74 00 } //3 FuckingShit
		$a_00_4 = {70 00 54 00 63 00 63 00 46 00 6e 00 6e 00 43 00 6d 00 6c 00 72 00 43 00 6a 00 44 00 77 00 36 00 } //4 pTccFnnCmlrCjDw6
		$a_00_5 = {46 00 61 00 73 00 74 00 6b 00 72 00 6f 00 61 00 6b 00 2e 00 65 00 78 00 65 00 } //3 Fastkroak.exe
		$a_01_6 = {46 61 73 74 6b 72 6f 61 6b } //3 Fastkroak
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*4+(#a_00_5  & 1)*3+(#a_01_6  & 1)*3) >=8
 
}
rule Trojan_BAT_AgentTesla_GE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 39 64 34 38 33 32 37 61 2d 39 30 33 66 2d 34 62 34 37 2d 38 64 64 36 2d 62 38 39 32 38 63 39 30 36 31 34 65 } //20 $9d48327a-903f-4b47-8dd6-b8928c90614e
		$a_81_1 = {24 35 31 65 30 32 39 30 35 2d 39 62 38 65 2d 34 65 61 30 2d 61 62 30 66 2d 62 65 37 35 31 30 31 38 64 35 62 66 } //20 $51e02905-9b8e-4ea0-ab0f-be751018d5bf
		$a_81_2 = {24 39 38 63 34 66 32 38 32 2d 65 33 30 65 2d 34 32 61 66 2d 38 61 36 33 2d 35 33 38 37 33 36 66 33 33 64 66 36 } //20 $98c4f282-e30e-42af-8a63-538736f33df6
		$a_81_3 = {24 34 63 37 38 65 39 64 37 2d 38 66 61 63 2d 34 37 33 35 2d 39 63 39 62 2d 62 38 31 33 61 62 66 62 63 30 35 39 } //20 $4c78e9d7-8fac-4735-9c9b-b813abfbc059
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