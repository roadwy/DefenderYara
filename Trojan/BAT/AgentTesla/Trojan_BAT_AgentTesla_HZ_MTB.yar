
rule Trojan_BAT_AgentTesla_HZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 14 00 "
		
	strings :
		$a_00_0 = {24 31 39 39 37 63 30 33 66 2d 61 65 66 61 2d 34 65 33 31 2d 39 38 39 31 2d 38 63 34 34 30 36 36 31 66 31 36 38 } //14 00  $1997c03f-aefa-4e31-9891-8c440661f168
		$a_00_1 = {24 30 62 66 39 32 65 31 66 2d 66 64 61 61 2d 34 33 39 61 2d 38 34 35 35 2d 64 61 35 39 63 61 37 61 33 33 33 62 } //14 00  $0bf92e1f-fdaa-439a-8455-da59ca7a333b
		$a_00_2 = {24 62 31 31 38 38 30 38 63 2d 63 65 39 64 2d 34 62 31 37 2d 62 32 38 66 2d 64 63 36 38 61 36 39 61 61 36 37 31 } //01 00  $b118808c-ce9d-4b17-b28f-dc68a69aa671
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}