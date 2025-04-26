
rule Trojan_BAT_AgentTesla_EO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {06 16 fe 01 0d 09 2c 1d 00 03 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 06 ?? ?? ?? 08 13 04 11 04 17 58 0c 08 07 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d b7 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_EO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 61 62 30 39 34 36 39 30 2d 36 38 30 37 2d 34 64 31 66 2d 61 33 34 38 2d 34 61 35 33 31 62 66 33 39 39 37 65 } //20 $ab094690-6807-4d1f-a348-4a531bf3997e
		$a_81_1 = {24 34 34 63 30 66 63 31 31 2d 36 35 37 37 2d 34 38 66 66 2d 39 32 36 64 2d 34 30 65 65 65 61 39 64 64 39 33 39 } //20 $44c0fc11-6577-48ff-926d-40eeea9dd939
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 76 65 6c 6f 70 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Develop.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {47 72 61 64 69 65 6e 74 50 69 63 6b 65 72 2e 58 2e 72 65 73 6f 75 72 63 65 73 } //1 GradientPicker.X.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_10 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=23
 
}