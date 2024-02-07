
rule Trojan_BAT_Formbook_EX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 38 34 30 65 35 31 63 31 2d 66 33 39 63 2d 34 32 31 38 2d 39 36 36 61 2d 64 38 64 62 30 65 35 62 39 35 34 39 } //01 00  $840e51c1-f39c-4218-966a-d8db0e5b9549
		$a_81_1 = {53 6f 63 6b 65 74 53 65 72 76 65 72 46 6f 72 6d 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  SocketServerForm.My.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}