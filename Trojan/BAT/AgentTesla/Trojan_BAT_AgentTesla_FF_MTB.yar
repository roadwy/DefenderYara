
rule Trojan_BAT_AgentTesla_FF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 50 8e 69 6a 5d b7 03 50 ?? 03 50 8e 69 6a 5d b7 91 ?? ?? ?? 8e 69 6a 5d b7 91 61 03 50 ?? 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_FF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 31 38 35 31 30 33 65 37 2d 63 30 32 66 2d 34 36 30 33 2d 38 36 34 34 2d 39 36 31 38 65 66 33 65 33 62 64 61 } //20 $185103e7-c02f-4603-8644-9618ef3e3bda
		$a_81_1 = {24 31 61 36 39 30 32 38 65 2d 34 63 39 61 2d 34 34 32 65 2d 38 38 33 36 2d 64 64 37 33 63 63 63 31 39 31 32 63 } //20 $1a69028e-4c9a-442e-8836-dd73ccc1912c
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {4f 77 6c 2e 43 6f 72 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Owl.Core.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {41 53 4d 61 6e 61 67 65 72 32 30 31 37 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 ASManager2017.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=24
 
}