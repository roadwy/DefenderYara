
rule Trojan_BAT_AgentTesla_GJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a2 25 17 7e 90 01 03 0a a2 25 18 11 06 a2 25 19 17 8c 90 01 03 01 a2 13 0a 11 09 11 07 90 00 } //01 00 
		$a_80_1 = {2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 } ////transfer.sh  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_GJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 63 65 30 32 37 64 32 66 2d 35 36 34 34 2d 34 30 37 38 2d 62 64 64 35 2d 32 35 32 36 64 36 38 65 61 36 63 34 } //14 00  $ce027d2f-5644-4078-bdd5-2526d68ea6c4
		$a_81_1 = {24 61 35 39 30 34 35 36 66 2d 34 61 30 64 2d 34 65 66 65 2d 38 63 36 63 2d 36 33 62 63 32 30 36 34 61 63 36 36 } //14 00  $a590456f-4a0d-4efe-8c6c-63bc2064ac66
		$a_81_2 = {24 62 34 66 32 65 64 66 36 2d 66 30 31 35 2d 34 39 30 30 2d 38 37 65 35 2d 65 65 32 33 61 30 32 31 35 64 37 31 } //01 00  $b4f2edf6-f015-4900-87e5-ee23a0215d71
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}