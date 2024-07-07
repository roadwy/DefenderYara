
rule Trojan_BAT_AgentTesla_DT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 33 64 61 61 38 39 38 30 2d 39 63 65 36 2d 34 37 36 61 2d 39 62 66 30 2d 63 66 38 66 37 35 66 30 35 62 66 33 } //20 $3daa8980-9ce6-476a-9bf0-cf8f75f05bf3
		$a_81_1 = {24 65 36 31 33 66 63 66 30 2d 34 35 63 62 2d 34 31 31 30 2d 39 63 61 37 2d 61 64 36 32 64 30 38 34 30 66 65 63 } //20 $e613fcf0-45cb-4110-9ca7-ad62d0840fec
		$a_81_2 = {6e 54 61 72 6c 61 73 69 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 nTarlasi.Form1.resources
		$a_81_3 = {43 6c 6f 63 6b 4c 6f 67 69 63 2e 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 ClockLogic.Main.resources
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=25
 
}