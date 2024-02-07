
rule Trojan_BAT_AgentTesla_LVP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 62 33 64 39 38 37 33 34 2d 66 35 32 37 2d 34 38 38 39 2d 38 65 39 65 2d 30 36 32 36 30 65 63 66 37 61 38 66 } //01 00  $b3d98734-f527-4889-8e9e-06260ecf7a8f
		$a_01_1 = {46 6c 6f 72 69 74 68 6d 65 74 69 63 } //01 00  Florithmetic
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}