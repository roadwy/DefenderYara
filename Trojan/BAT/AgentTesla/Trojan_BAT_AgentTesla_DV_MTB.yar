
rule Trojan_BAT_AgentTesla_DV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0d 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 36 37 34 30 63 61 38 39 2d 35 35 33 38 2d 34 39 62 38 2d 39 63 33 34 2d 39 33 61 62 36 31 66 66 36 61 62 63 } //14 00  $6740ca89-5538-49b8-9c34-93ab61ff6abc
		$a_81_1 = {24 64 32 34 66 66 66 33 65 2d 36 37 62 33 2d 34 62 31 31 2d 39 30 34 38 2d 62 33 61 38 66 33 62 66 34 38 65 30 } //01 00  $d24fff3e-67b3-4b11-9048-b3a8f3bf48e0
		$a_81_2 = {4d 65 6d 62 65 72 4d 61 6e 61 67 65 72 4c 69 74 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  MemberManagerLite.Resources.resources
		$a_81_3 = {43 61 73 69 6e 6f 47 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  CasinoGame.Resources.resources
		$a_81_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}