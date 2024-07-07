
rule Trojan_BAT_AgentTesla_ET_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 03 11 05 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 07 08 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 06 00 1f fb 13 07 90 00 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_ET_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 "
		
	strings :
		$a_01_0 = {24 33 35 35 46 35 32 38 31 2d 33 42 34 31 2d 34 34 44 43 2d 39 30 46 33 2d 37 33 36 43 33 39 39 33 30 32 44 30 } //20 $355F5281-3B41-44DC-90F3-736C399302D0
		$a_81_1 = {24 64 37 34 34 39 30 37 65 2d 63 35 30 65 2d 34 64 35 31 2d 61 62 64 39 2d 61 36 31 62 64 64 39 65 33 61 31 65 } //20 $d744907e-c50e-4d51-abd9-a61bdd9e3a1e
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {56 69 62 6f 72 69 74 61 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Viborita.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {53 75 70 65 72 41 64 76 65 6e 74 75 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 SuperAdventure.Properties.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=24
 
}