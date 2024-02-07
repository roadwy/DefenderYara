
rule Trojan_BAT_AgentTesla_JOJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 32 39 62 37 35 63 64 38 2d 63 66 63 37 2d 34 34 31 65 2d 38 35 63 61 2d 38 39 30 35 39 65 35 63 37 32 39 31 } //01 00  $29b75cd8-cfc7-441e-85ca-89059e5c7291
		$a_81_1 = {47 61 6d 65 } //01 00  Game
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {53 70 6c 69 74 } //01 00  Split
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}