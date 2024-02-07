
rule Trojan_BAT_AgentTesla_DQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0d 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 34 37 35 64 63 37 36 36 2d 37 30 35 37 2d 34 33 32 30 2d 61 66 30 63 2d 61 64 63 36 35 37 65 36 39 64 30 62 } //14 00  $475dc766-7057-4320-af0c-adc657e69d0b
		$a_81_1 = {24 33 62 38 64 34 36 63 30 2d 34 36 63 33 2d 34 36 66 34 2d 39 38 63 35 2d 38 61 64 39 64 66 30 65 34 31 61 36 } //01 00  $3b8d46c0-46c3-46f4-98c5-8ad9df0e41a6
		$a_81_2 = {46 6f 72 6d 73 43 6c 61 73 73 65 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  FormsClasses.Properties.Resources
		$a_81_3 = {44 73 6b 45 78 70 6c 6f 72 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  DskExplorer.My.Resources
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