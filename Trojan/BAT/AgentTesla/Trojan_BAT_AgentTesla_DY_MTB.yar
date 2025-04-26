
rule Trojan_BAT_AgentTesla_DY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 32 62 31 63 39 37 37 36 2d 30 38 61 62 2d 34 39 64 65 2d 39 37 33 65 2d 32 38 33 64 65 63 61 39 34 61 31 64 } //20 $2b1c9776-08ab-49de-973e-283deca94a1d
		$a_81_1 = {24 30 65 32 33 66 30 62 37 2d 61 65 65 31 2d 34 36 30 31 2d 61 64 31 38 2d 31 36 30 38 32 62 38 37 31 61 32 35 } //20 $0e23f0b7-aee1-4601-ad18-16082b871a25
		$a_81_2 = {6a 6f 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 job.Properties.Resources
		$a_81_3 = {52 6f 63 6b 65 74 5f 4d 69 73 73 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Rocket_Mission.Properties.Resources
		$a_81_4 = {4d 6f 64 75 6c 65 52 65 73 6f 6c 76 65 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 ModuleResolveEventHandler
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_8 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_10 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=23
 
}