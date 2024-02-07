
rule Trojan_BAT_Racealer_DA_MTB{
	meta:
		description = "Trojan:BAT/Racealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 34 33 36 35 62 65 65 34 2d 31 62 32 34 2d 34 62 35 66 2d 38 31 35 65 2d 64 35 34 30 38 64 65 61 38 36 33 39 } //05 00  $4365bee4-1b24-4b5f-815e-d5408dea8639
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //05 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_3 = {4f 6e 53 63 72 65 65 6e 4b 65 79 62 6f 61 72 64 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  OnScreenKeyboard.Properties.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}